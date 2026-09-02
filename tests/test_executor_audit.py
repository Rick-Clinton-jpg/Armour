import json
import tempfile
import unittest
from pathlib import Path

from armour import (
    ActionProposal, ArmourGate, AuditStatus, Effect, GuardedExecutor,
    HMACApprovalVerifier, HumanApproval, Policy, ReceiptLog, Risk,
)


class ExecutorAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def executor(self, actions, log=None):
        policy = Policy(
            allowed_actions=frozenset(actions),
            action_effects={action: Effect.READ_ONLY for action in actions},
        )
        return GuardedExecutor(ArmourGate(policy), log)

    def test_only_registered_handlers_execute(self):
        outcome = self.executor({"echo"}).execute(
            ActionProposal("echo", Effect.READ_ONLY, Risk.LOW)
        )
        self.assertFalse(outcome.success)
        self.assertIn("no registered handler", outcome.error)

    def test_registered_handler_executes_and_is_audited(self):
        log = ReceiptLog(self.root / "receipts.jsonl")
        executor = self.executor({"echo"}, log)
        executor.register("echo", lambda proposal: proposal.payload["text"])
        proposal = ActionProposal("echo", Effect.READ_ONLY, Risk.LOW, payload={"text": "hello"})
        outcome = executor.execute(proposal)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.output, "hello")
        self.assertIs(outcome.audit_status, AuditStatus.COMPLETED)
        self.assertIsNone(outcome.audit_error)
        self.assertTrue(log.verify())
        records = [json.loads(line) for line in log.path.read_text().splitlines()]
        self.assertEqual(records[0]["decision"]["verdict"], "authorized")
        self.assertEqual(records[1]["outcome"]["audit_status"], "completed")

    def test_completion_audit_failure_preserves_success_and_output(self):
        class CompletionFailingReceipts:
            def append(self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                if phase == "completed":
                    raise OSError("disk full")

        effects = []
        executor = self.executor({"send"}, CompletionFailingReceipts())
        executor.register("send", lambda _proposal: effects.append("sent") or "message-id")

        outcome = executor.execute(ActionProposal("send", Effect.READ_ONLY, Risk.LOW))

        self.assertEqual(effects, ["sent"])
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.output, "message-id")
        self.assertIsNone(outcome.error)
        self.assertIs(outcome.audit_status, AuditStatus.COMPLETION_FAILED)
        self.assertEqual(outcome.audit_error, "audit completion failed: OSError")
        self.assertIsNotNone(outcome.execution_id)

    def test_start_audit_failure_never_runs_handler(self):
        class StartFailingReceipts:
            def append(self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                raise OSError("disk unavailable")

        effects = []
        executor = self.executor({"send"}, StartFailingReceipts())
        executor.register("send", lambda _proposal: effects.append("sent"))

        outcome = executor.execute(ActionProposal("send", Effect.READ_ONLY, Risk.LOW))

        self.assertEqual(effects, [])
        self.assertFalse(outcome.success)
        self.assertIs(outcome.audit_status, AuditStatus.START_FAILED)
        self.assertEqual(outcome.audit_error, "audit start failed: OSError")

    def test_completion_audit_failure_preserves_handler_failure(self):
        class CompletionFailingReceipts:
            def append(self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                if phase == "completed":
                    raise OSError("disk full")

        executor = self.executor({"send"}, CompletionFailingReceipts())

        def fail(_proposal):
            raise RuntimeError("handler failed")

        executor.register("send", fail)
        outcome = executor.execute(ActionProposal("send", Effect.READ_ONLY, Risk.LOW))

        self.assertFalse(outcome.success)
        self.assertEqual(outcome.error, "RuntimeError: handler failed")
        self.assertIs(outcome.audit_status, AuditStatus.COMPLETION_FAILED)
        self.assertEqual(outcome.audit_error, "audit completion failed: OSError")

    def test_tampered_receipt_chain_is_detected(self):
        log = ReceiptLog(self.root / "receipts.jsonl")
        executor = self.executor({"echo"}, log)
        executor.register("echo", lambda proposal: "ok")
        executor.execute(ActionProposal("echo", Effect.READ_ONLY, Risk.LOW))
        log.path.write_text(log.path.read_text().replace('"output": "ok"', '"output": "changed"'))
        self.assertFalse(log.verify())

    def test_handler_exception_is_contained(self):
        executor = self.executor({"boom"})

        def boom(_proposal):
            raise RuntimeError("failure")

        executor.register("boom", boom)
        outcome = executor.execute(ActionProposal("boom", Effect.READ_ONLY, Risk.LOW))
        self.assertFalse(outcome.success)
        self.assertEqual(outcome.error, "RuntimeError: failure")

    def test_approval_is_single_use(self):
        log = ReceiptLog(self.root / "approval-receipts.jsonl")
        policy = Policy(
            allowed_actions=frozenset({"delete"}),
            action_effects={"delete": Effect.DESTRUCTIVE},
        )
        approval_key = b"test-approval-key"
        executor = GuardedExecutor(
            ArmourGate(
                policy,
                approval_verifier=HMACApprovalVerifier({"test-key": approval_key}),
            ),
            log,
        )
        executor.register("delete", lambda proposal: "done")
        proposal = ActionProposal("delete", Effect.READ_ONLY, Risk.LOW)
        approval = HumanApproval.issue(
            proposal,
            policy_fingerprint=policy.fingerprint(),
            approved_by="test-human",
            signing_key=approval_key,
            key_id="test-key",
        )
        self.assertTrue(executor.execute(proposal, approval=approval).success)
        record = json.loads(log.path.read_text().splitlines()[0])
        self.assertEqual(record["decision"]["approved_by"], "test-human")
        self.assertEqual(record["decision"]["approval_nonce"], approval.nonce)
        self.assertEqual(
            record["decision"]["policy_fingerprint"], policy.fingerprint()
        )
        replay = executor.execute(proposal, approval=approval)
        self.assertFalse(replay.success)
        self.assertEqual(replay.error, "Armour decision: escalated")


if __name__ == "__main__":
    unittest.main()
