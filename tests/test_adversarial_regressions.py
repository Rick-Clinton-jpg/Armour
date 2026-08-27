import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from armour import (
    ActionProposal,
    ActionSchema,
    ArmourGate,
    Effect,
    GuardedExecutor,
    HMACApprovalVerifier,
    HumanApproval,
    Policy,
    ReceiptIntegrityError,
    ReceiptLog,
    Risk,
    Verdict,
)
from armour.verifiers import NetworkVerifier


class AdversarialRegressionTests(unittest.TestCase):
    def test_policy_copies_mutable_authority_collections(self):
        actions = {"read"}
        methods = {"GET"}
        forbidden = {Effect.IRREVERSIBLE}
        policy = Policy(
            allowed_actions=actions,
            action_effects={"read": Effect.READ_ONLY},
            allowed_http_methods=methods,
            forbidden_effects=forbidden,
        )
        fingerprint = policy.fingerprint()
        actions.add("invented")
        methods.add("POST")
        forbidden.clear()
        self.assertEqual(policy.allowed_actions, frozenset({"read"}))
        self.assertEqual(policy.allowed_http_methods, frozenset({"GET"}))
        self.assertEqual(policy.forbidden_effects, frozenset({Effect.IRREVERSIBLE}))
        self.assertEqual(policy.fingerprint(), fingerprint)

    def test_policy_integrity_drift_fails_closed(self):
        policy = Policy(
            allowed_actions=frozenset({"fetch"}),
            action_effects={"fetch": Effect.READ_ONLY},
        )
        object.__setattr__(policy, "deny_private_networks", False)
        proposal = ActionProposal("fetch", Effect.READ_ONLY, Risk.LOW)
        with self.assertLogs("armour.gate", level="ERROR"):
            decision = ArmourGate(policy).evaluate(proposal)
        self.assertIs(decision.verdict, Verdict.REJECTED)
        self.assertIn("policy integrity verification failed", decision.reasons)

    def test_unknown_policy_fields_are_rejected(self):
        with self.assertRaises(TypeError):
            Policy(
                allowed_actions=frozenset({"read"}),
                action_effects={"read": Effect.READ_ONLY},
                future_authority=True,
            )

    def test_nul_path_is_rejected_without_raising(self):
        with tempfile.TemporaryDirectory() as folder:
            policy = Policy(
                allowed_actions=frozenset({"read"}),
                action_effects={"read": Effect.READ_ONLY},
                allowed_roots=(Path(folder),),
            )
            proposal = ActionProposal(
                "read", Effect.READ_ONLY, Risk.LOW, resource=f"{folder}/bad\x00path"
            )
            self.assertIs(ArmourGate(policy).evaluate(proposal).verdict, Verdict.REJECTED)

    def test_non_string_payload_method_is_rejected_without_raising(self):
        policy = Policy(
            allowed_actions=frozenset({"fetch"}),
            action_effects={"fetch": Effect.READ_ONLY},
        )
        proposal = ActionProposal(
            "fetch",
            Effect.READ_ONLY,
            Risk.LOW,
            resource="https://example.com",
            payload={"method": 7},
        )
        gate = ArmourGate(
            policy,
            network_verifier=NetworkVerifier(
                resolver=lambda _host: ["93.184.216.34"]
            ),
        )
        decision = gate.evaluate(proposal)
        self.assertIs(decision.verdict, Verdict.REJECTED)
        self.assertIn("HTTP method must be a string", decision.reasons)

    def test_verifier_exception_becomes_rejection_evidence(self):
        class BrokenVerifier:
            name = "broken_test_verifier"

            def check(self, proposal, policy):
                raise RuntimeError("secret internal detail")

        policy = Policy(
            allowed_actions=frozenset({"read"}),
            action_effects={"read": Effect.READ_ONLY},
        )
        with self.assertLogs("armour.gate", level="ERROR"):
            decision = ArmourGate(
                policy, additional_verifiers=(BrokenVerifier(),)
            ).evaluate(ActionProposal("read", Effect.READ_ONLY, Risk.LOW))
        self.assertIs(decision.verdict, Verdict.REJECTED)
        self.assertIn("verifier_error:broken_test_verifier", decision.reasons)
        self.assertNotIn("secret internal detail", decision.reasons)

    def test_unsigned_or_tampered_approval_is_not_trusted(self):
        key = b"trusted-test-key"
        verifier = HMACApprovalVerifier({"human-review": key})
        policy = Policy(
            allowed_actions=frozenset({"delete"}),
            action_effects={"delete": Effect.DESTRUCTIVE},
        )
        proposal = ActionProposal("delete", Effect.DESTRUCTIVE, Risk.HIGH)
        unsigned = HumanApproval.issue(
            proposal,
            policy_fingerprint=policy.fingerprint(),
            approved_by="attacker",
        )
        gate = ArmourGate(policy, approval_verifier=verifier)
        self.assertIs(
            gate.evaluate(proposal, approval=unsigned).verdict, Verdict.ESCALATED
        )
        signed = HumanApproval.issue(
            proposal,
            policy_fingerprint=policy.fingerprint(),
            approved_by="reviewer",
            signing_key=key,
            key_id="human-review",
        )
        self.assertIs(
            gate.evaluate(proposal, approval=signed).verdict, Verdict.AUTHORIZED
        )
        tampered = replace(signed, approved_by="attacker")
        self.assertIs(
            gate.evaluate(proposal, approval=tampered).verdict, Verdict.ESCALATED
        )

    def test_corrupt_receipt_returns_diagnostic_and_refuses_append(self):
        with tempfile.TemporaryDirectory() as folder:
            log = ReceiptLog(Path(folder) / "receipts.jsonl")
            log.path.write_text("{not-json}\n", encoding="utf-8")
            result = log.verify()
            self.assertFalse(result)
            self.assertEqual(result.failed_record, 1)
            self.assertIn("invalid JSON", result.reason)
            policy = Policy(
                allowed_actions=frozenset({"read"}),
                action_effects={"read": Effect.READ_ONLY},
            )
            proposal = ActionProposal("read", Effect.READ_ONLY, Risk.LOW)
            decision = ArmourGate(policy).evaluate(proposal)
            with self.assertRaises(ReceiptIntegrityError):
                log.append(proposal, decision)

    def test_execution_is_staged_and_cyclic_output_is_sanitized(self):
        with tempfile.TemporaryDirectory() as folder:
            log = ReceiptLog(Path(folder) / "receipts.jsonl")
            policy = Policy(
                allowed_actions=frozenset({"effect"}),
                action_effects={"effect": Effect.STATE_CHANGING},
            )
            marker = Path(folder) / "marker"
            executor = GuardedExecutor(ArmourGate(policy), log)

            def handler(_proposal):
                marker.write_text("done", encoding="utf-8")
                cyclic = []
                cyclic.append(cyclic)
                return cyclic

            executor.register("effect", handler)
            outcome = executor.execute(
                ActionProposal("effect", Effect.STATE_CHANGING, Risk.MEDIUM)
            )
            self.assertTrue(outcome.success)
            self.assertTrue(marker.exists())
            records = [json.loads(line) for line in log.path.read_text().splitlines()]
            self.assertEqual([record["phase"] for record in records], ["started", "completed"])
            self.assertEqual(records[1]["outcome"]["output"], ["<cycle>"])
            self.assertTrue(log.verify())

    def test_nested_filesystem_alias_is_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            policy = Policy(
                allowed_actions=frozenset({"copy"}),
                action_effects={"copy": Effect.STATE_CHANGING},
                action_schemas={
                    "copy": ActionSchema(
                        allowed_payload_keys=frozenset({"source", "destination"}),
                        required_payload_keys=frozenset({"source", "destination"}),
                        filesystem_path_fields=frozenset({"source", "destination"}),
                    )
                },
                allowed_roots=(Path(folder),),
            )
            proposal = ActionProposal(
                "copy",
                Effect.STATE_CHANGING,
                Risk.MEDIUM,
                payload={"options": {"source": "/etc/passwd"}},
            )
            self.assertIs(ArmourGate(policy).evaluate(proposal).verdict, Verdict.REJECTED)

    def test_sentence_boundary_normalization_remains_advisory(self):
        policy = Policy(
            allowed_actions=frozenset({"task"}),
            action_effects={"task": Effect.STATE_CHANGING},
        )
        proposal = ActionProposal(
            "task",
            Effect.STATE_CHANGING,
            Risk.MEDIUM,
            payload={"text": "DR. OP TABLE records"},
        )
        self.assertIs(ArmourGate(policy).evaluate(proposal).verdict, Verdict.REJECTED)


if __name__ == "__main__":
    unittest.main()
