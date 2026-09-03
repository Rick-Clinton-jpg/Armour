import json
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from armour import (
    ActionProposal,
    ArmourGate,
    AuditStatus,
    BindingConsumed,
    BindingExpired,
    BindingMismatch,
    DependencyPolicy,
    Effect,
    FilesystemBinder,
    GuardedExecutor,
    Policy,
    ReceiptLog,
    Risk,
    UnsafePathError,
    prepare_execution_binding,
)


class FakeClock:
    def __init__(self) -> None:
        self.now_ns = 1_000_000_000

    def __call__(self) -> int:
        return self.now_ns

    def advance_ms(self, milliseconds: float) -> None:
        self.now_ns += int(milliseconds * 1_000_000)


@unittest.skipUnless(
    os.open in os.supports_dir_fd
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY"),
    "directory-relative no-follow opens are unavailable",
)
class ExecutionBindingInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root"
        self.outside = Path(self.temp.name) / "outside"
        self.root.mkdir()
        self.outside.mkdir()
        self.path = self.root / "note.txt"
        self.path.write_text("safe", encoding="utf-8")
        self.secret = self.outside / "secret.txt"
        self.secret.write_text("secret", encoding="utf-8")
        self.clock = FakeClock()
        self.policy = Policy(
            allowed_actions=frozenset({"read_file"}),
            action_effects={"read_file": Effect.READ_ONLY},
            allowed_roots=(self.root,),
            action_dependencies={
                "read_file": {
                    "resource": DependencyPolicy(kind="filesystem", max_age_ms=25),
                }
            },
            policy_id="binding-tests",
        )
        self.proposal = ActionProposal(
            "read_file", Effect.READ_ONLY, Risk.LOW, resource=str(self.path)
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare(self, proposal=None, policy=None, execution_id="exec-1"):
        return prepare_execution_binding(
            proposal or self.proposal,
            policy or self.policy,
            execution_id=execution_id,
            binders={"resource": FilesystemBinder()},
            monotonic_ns=self.clock,
        )

    def test_binding_is_bound_to_exact_proposal_fingerprint(self):
        binding = self.prepare()
        changed = replace(self.proposal, id="different")
        with self.assertRaises(BindingMismatch):
            binding.consume(
                proposal=changed,
                policy_fingerprint=self.policy.fingerprint(),
                execution_id="exec-1",
            )
        binding.close()

    def test_binding_is_bound_to_exact_policy_fingerprint(self):
        binding = self.prepare()
        revised = replace(self.policy, revision=2)
        with self.assertRaises(BindingMismatch):
            binding.consume(
                proposal=self.proposal,
                policy_fingerprint=revised.fingerprint(),
                execution_id="exec-1",
            )
        binding.close()

    def test_binding_is_bound_to_one_execution_id(self):
        binding = self.prepare()
        with self.assertRaises(BindingMismatch):
            binding.consume(
                proposal=self.proposal,
                policy_fingerprint=self.policy.fingerprint(),
                execution_id="exec-2",
            )
        binding.close()

    def test_binding_is_single_use(self):
        binding = self.prepare()
        context = binding.consume(
            proposal=self.proposal,
            policy_fingerprint=self.policy.fingerprint(),
            execution_id="exec-1",
        )
        with self.assertRaises(BindingConsumed):
            binding.consume(
                proposal=self.proposal,
                policy_fingerprint=self.policy.fingerprint(),
                execution_id="exec-1",
            )
        context.close()

    def test_concurrent_consumers_cannot_use_one_binding_twice(self):
        binding = self.prepare()
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def consume():
            barrier.wait()
            try:
                context = binding.consume(
                    proposal=self.proposal,
                    policy_fingerprint=self.policy.fingerprint(),
                    execution_id="exec-1",
                )
            except BindingConsumed:
                result = "consumed"
            else:
                result = "ok"
                context.close()
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(outcomes, ["ok", "consumed"])

    def test_expired_binding_prevents_consumption(self):
        binding = self.prepare()
        self.clock.advance_ms(26)
        with self.assertRaises(BindingExpired):
            binding.consume(
                proposal=self.proposal,
                policy_fingerprint=self.policy.fingerprint(),
                execution_id="exec-1",
            )
        binding.close()

    def test_bound_file_checks_deadline_again_at_actual_access(self):
        binding = self.prepare()
        context = binding.consume(
            proposal=self.proposal,
            policy_fingerprint=self.policy.fingerprint(),
            execution_id="exec-1",
        )
        capability = context.capability("resource")
        self.clock.advance_ms(25)
        with self.assertRaises(BindingExpired):
            capability.read_text()
        context.close()

    def test_dependency_policy_changes_policy_fingerprint(self):
        revised = replace(
            self.policy,
            action_dependencies={
                "read_file": {
                    "resource": DependencyPolicy(kind="filesystem", max_age_ms=10),
                }
            },
        )
        self.assertNotEqual(self.policy.fingerprint(), revised.fingerprint())

    def test_agent_cannot_select_dependency_class_or_extend_deadline(self):
        proposal = ActionProposal.from_untrusted(
            {
                "action": "read_file",
                "effect": "read_only",
                "risk": "low",
                "resource": str(self.path),
                "dependency_class": "anything",
                "max_age_ms": 999_999,
            }
        )
        binding = self.prepare(proposal=proposal)
        self.clock.advance_ms(26)
        with self.assertRaises(BindingExpired):
            binding.consume(
                proposal=proposal,
                policy_fingerprint=self.policy.fingerprint(),
                execution_id="exec-1",
            )
        binding.close()

    def test_cross_proposal_transplant_is_rejected(self):
        binding = self.prepare()
        other = replace(self.proposal, id="other-proposal")
        with self.assertRaises(BindingMismatch):
            binding.consume(
                proposal=other,
                policy_fingerprint=self.policy.fingerprint(),
                execution_id="exec-1",
            )
        binding.close()

    def test_ordinary_handler_cannot_register_for_bound_action(self):
        executor = GuardedExecutor(ArmourGate(self.policy))
        with self.assertRaisesRegex(ValueError, "requires execution binding"):
            executor.register("read_file", lambda proposal: proposal.resource)

    def test_missing_required_binder_prevents_registration(self):
        executor = GuardedExecutor(ArmourGate(self.policy))
        with self.assertRaisesRegex(ValueError, "binder set"):
            executor.register_bound("read_file", lambda proposal, context: None, {})

    def test_mismatched_binder_kind_prevents_registration(self):
        class WrongBinder:
            kind = "network"

        executor = GuardedExecutor(ArmourGate(self.policy))
        with self.assertRaisesRegex(ValueError, "binder kind"):
            executor.register_bound(
                "read_file",
                lambda proposal, context: None,
                {"resource": WrongBinder()},
            )

    def test_dependency_policy_is_deeply_immutable(self):
        with self.assertRaises(TypeError):
            self.policy.action_dependencies["read_file"]["resource"] = DependencyPolicy(
                kind="filesystem", max_age_ms=1
            )

    def test_handler_reads_from_bound_file(self):
        executor = GuardedExecutor(ArmourGate(self.policy), monotonic_ns=self.clock)
        executor.register_bound(
            "read_file",
            lambda _proposal, context: context.capability("resource").read_text(),
            {"resource": FilesystemBinder()},
        )
        outcome = executor.execute(self.proposal)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.output, "safe")
        self.assertIsNotNone(outcome.binding_id)

    def test_path_replacement_after_binding_does_not_redirect_handler(self):
        class SwappingReceipts:
            def append(inner_self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                if phase == "started" and self.path.exists():
                    self.path.rename(self.root / "original.txt")
                    self.path.symlink_to(self.secret)

        executor = GuardedExecutor(
            ArmourGate(self.policy), SwappingReceipts(), monotonic_ns=self.clock
        )
        executor.register_bound(
            "read_file",
            lambda _proposal, context: context.capability("resource").read_text(),
            {"resource": FilesystemBinder()},
        )
        outcome = executor.execute(self.proposal)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.output, "safe")
        self.assertNotEqual(outcome.output, "secret")

    def test_symlink_is_rejected_before_handler_execution(self):
        self.path.unlink()
        self.path.symlink_to(self.secret)
        effects = []
        executor = GuardedExecutor(ArmourGate(self.policy), monotonic_ns=self.clock)
        executor.register_bound(
            "read_file",
            lambda _proposal, _context: effects.append("ran"),
            {"resource": FilesystemBinder()},
        )
        outcome = executor.execute(self.proposal)
        self.assertFalse(outcome.success)
        self.assertEqual(effects, [])
        self.assertTrue(
            "binding failed" in outcome.error or "Armour decision: rejected" in outcome.error
        )

    def test_intermediate_symlink_is_rejected_by_binder(self):
        link = self.root / "linked"
        link.symlink_to(self.outside, target_is_directory=True)
        proposal = replace(self.proposal, resource=str(link / "secret.txt"))
        with self.assertRaises(UnsafePathError):
            self.prepare(proposal=proposal)

    def test_non_regular_resource_is_rejected_by_binder(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        proposal = replace(self.proposal, resource=str(fifo))
        with self.assertRaises(UnsafePathError):
            self.prepare(proposal=proposal)

    def test_binding_expiring_during_audit_prevents_handler(self):
        class SlowReceipts:
            def append(inner_self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                if phase == "started":
                    self.clock.advance_ms(26)

        effects = []
        executor = GuardedExecutor(
            ArmourGate(self.policy), SlowReceipts(), monotonic_ns=self.clock
        )
        executor.register_bound(
            "read_file",
            lambda _proposal, _context: effects.append("ran"),
            {"resource": FilesystemBinder()},
        )
        outcome = executor.execute(self.proposal)
        self.assertFalse(outcome.success)
        self.assertEqual(effects, [])
        self.assertIn("binding expired", outcome.error)

    def test_audit_start_failure_prevents_handler_and_closes_capability(self):
        class BrokenReceipts:
            def append(self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                raise OSError("unavailable")

        effects = []
        binder = FilesystemBinder()
        executor = GuardedExecutor(
            ArmourGate(self.policy), BrokenReceipts(), monotonic_ns=self.clock
        )
        executor.register_bound(
            "read_file",
            lambda _proposal, _context: effects.append("ran"),
            {"resource": binder},
        )
        outcome = executor.execute(self.proposal)
        self.assertFalse(outcome.success)
        self.assertEqual(effects, [])
        self.assertIs(outcome.audit_status, AuditStatus.START_FAILED)
        self.assertTrue(binder.last_capability.closed)

    def test_capability_closes_after_success_and_handler_failure(self):
        for raises in (False, True):
            with self.subTest(raises=raises):
                binder = FilesystemBinder()
                executor = GuardedExecutor(ArmourGate(self.policy), monotonic_ns=self.clock)

                def handler(_proposal, context):
                    context.capability("resource")
                    if raises:
                        raise RuntimeError("failure")
                    return "ok"

                executor.register_bound("read_file", handler, {"resource": binder})
                executor.execute(self.proposal)
                self.assertTrue(binder.last_capability.closed)

    def test_completion_audit_failure_preserves_bound_handler_success(self):
        class CompletionFailure:
            def append(self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                if phase == "completed":
                    raise OSError("unavailable")

        binder = FilesystemBinder()
        executor = GuardedExecutor(
            ArmourGate(self.policy), CompletionFailure(), monotonic_ns=self.clock
        )
        executor.register_bound(
            "read_file",
            lambda _proposal, context: context.capability("resource").read_text(),
            {"resource": binder},
        )
        outcome = executor.execute(self.proposal)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.output, "safe")
        self.assertIs(outcome.audit_status, AuditStatus.COMPLETION_FAILED)
        self.assertTrue(binder.last_capability.closed)

    def test_completion_receipt_records_binding_id(self):
        receipt_path = Path(self.temp.name) / "receipts.jsonl"
        executor = GuardedExecutor(
            ArmourGate(self.policy), ReceiptLog(receipt_path), monotonic_ns=self.clock
        )
        executor.register_bound(
            "read_file",
            lambda _proposal, context: context.capability("resource").read_text(),
            {"resource": FilesystemBinder()},
        )
        outcome = executor.execute(self.proposal)
        records = [json.loads(line) for line in receipt_path.read_text().splitlines()]
        self.assertEqual(records[-1]["outcome"]["binding_id"], outcome.binding_id)


if __name__ == "__main__":
    unittest.main()
