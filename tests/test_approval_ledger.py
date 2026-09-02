import hashlib
import hmac
import sqlite3
import stat
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from armour import (
    ActionProposal,
    ApprovalLedgerError,
    ArmourGate,
    Effect,
    HMACApprovalVerifier,
    HumanApproval,
    Policy,
    Risk,
    SQLiteApprovalLedger,
    Verdict,
)


class ApprovalLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "approval-ledger.sqlite3"
        self.key = b"durable-approval-test-key"
        self.verifier = HMACApprovalVerifier({"reviewer-key": self.key})
        self.policy = Policy(
            allowed_actions=frozenset({"delete"}),
            action_effects={"delete": Effect.DESTRUCTIVE},
            policy_id="durable-test",
        )
        self.proposal = ActionProposal("delete", Effect.DESTRUCTIVE, Risk.HIGH)
        self.approval = HumanApproval.issue(
            self.proposal,
            policy_fingerprint=self.policy.fingerprint(),
            approved_by="reviewer",
            signing_key=self.key,
            key_id="reviewer-key",
        )

    def tearDown(self):
        self.temp.cleanup()

    def gate(self, ledger=None, **kwargs):
        return ArmourGate(
            self.policy,
            approval_verifier=self.verifier,
            approval_ledger=ledger,
            **kwargs,
        )

    def resign(self, approval):
        return replace(
            approval,
            signature=hmac.new(
                self.key, approval.canonical_payload(), hashlib.sha256
            ).hexdigest(),
        )

    def test_approval_replay_is_rejected_after_restart(self):
        first = self.gate(SQLiteApprovalLedger(self.database))
        self.assertIs(
            first.evaluate(self.proposal, approval=self.approval).verdict,
            Verdict.AUTHORIZED,
        )
        restarted = self.gate(SQLiteApprovalLedger(self.database))
        replay = restarted.evaluate(self.proposal, approval=self.approval)
        self.assertIs(replay.verdict, Verdict.ESCALATED)
        self.assertIn("approval nonce already consumed", replay.reasons)

    def test_two_governors_cannot_claim_the_same_approval(self):
        gates = [
            self.gate(SQLiteApprovalLedger(self.database)),
            self.gate(SQLiteApprovalLedger(self.database)),
        ]
        barrier = threading.Barrier(2)
        verdicts = []
        result_lock = threading.Lock()

        def evaluate(gate):
            barrier.wait()
            verdict = gate.evaluate(self.proposal, approval=self.approval).verdict
            with result_lock:
                verdicts.append(verdict)

        threads = [threading.Thread(target=evaluate, args=(gate,)) for gate in gates]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(verdicts, [Verdict.AUTHORIZED, Verdict.ESCALATED])

    def test_policy_change_does_not_reset_nonce_history(self):
        first = self.gate(SQLiteApprovalLedger(self.database))
        self.assertIs(
            first.evaluate(self.proposal, approval=self.approval).verdict,
            Verdict.AUTHORIZED,
        )
        revised_policy = replace(self.policy, revision=2)
        revised_proposal = replace(self.proposal, id="revised-proposal")
        revised_approval = HumanApproval.issue(
            revised_proposal,
            policy_fingerprint=revised_policy.fingerprint(),
            approved_by="reviewer",
            signing_key=self.key,
            key_id="reviewer-key",
        )
        revised_approval = self.resign(
            replace(revised_approval, nonce=self.approval.nonce, signature="")
        )
        replay = ArmourGate(
            revised_policy,
            approval_verifier=self.verifier,
            approval_ledger=SQLiteApprovalLedger(self.database),
        ).evaluate(revised_proposal, approval=revised_approval)
        self.assertIs(replay.verdict, Verdict.ESCALATED)
        self.assertIn("approval nonce already consumed", replay.reasons)

    def test_invalid_signature_cannot_poison_nonce(self):
        ledger = SQLiteApprovalLedger(self.database)
        invalid = replace(self.approval, signature="invalid")
        self.assertIs(
            self.gate(ledger).evaluate(self.proposal, approval=invalid).verdict,
            Verdict.ESCALATED,
        )
        self.assertEqual(ledger.claims(), ())
        self.assertIs(
            self.gate(ledger).evaluate(
                self.proposal, approval=self.approval
            ).verdict,
            Verdict.AUTHORIZED,
        )

    def test_ledger_failure_fails_closed(self):
        class BrokenLedger:
            durable = True

            def claim(self, approval):
                raise ApprovalLedgerError("database unavailable")

        with self.assertLogs("armour.gate", level="ERROR"):
            decision = self.gate(BrokenLedger()).evaluate(
                self.proposal, approval=self.approval
            )
        self.assertIs(decision.verdict, Verdict.ESCALATED)
        self.assertIn("approval replay ledger unavailable", decision.reasons)

    def test_signed_approval_is_consumed_by_default(self):
        gate = self.gate()
        self.assertIs(
            gate.evaluate(self.proposal, approval=self.approval).verdict,
            Verdict.AUTHORIZED,
        )
        self.assertIs(
            gate.evaluate(self.proposal, approval=self.approval).verdict,
            Verdict.ESCALATED,
        )

    def test_explicit_preview_does_not_consume_approval(self):
        gate = self.gate()
        self.assertIs(
            gate.evaluate(
                self.proposal, approval=self.approval, consume_approval=False
            ).verdict,
            Verdict.AUTHORIZED,
        )
        self.assertIs(
            gate.evaluate(self.proposal, approval=self.approval).verdict,
            Verdict.AUTHORIZED,
        )

    def test_production_mode_requires_verifier_and_durable_ledger(self):
        with self.assertRaisesRegex(ValueError, "trusted approval verifier"):
            ArmourGate(
                self.policy,
                approval_ledger=SQLiteApprovalLedger(self.database),
                production_mode=True,
            )
        with self.assertRaisesRegex(ValueError, "durable approval ledger"):
            ArmourGate(
                self.policy,
                approval_verifier=self.verifier,
                production_mode=True,
            )
        gate = self.gate(
            SQLiteApprovalLedger(self.database), production_mode=True
        )
        self.assertEqual(gate.security_report()["weaknesses"], ())
        factory_gate = ArmourGate.production(
            self.policy,
            approval_verifier=self.verifier,
            approval_ledger=SQLiteApprovalLedger(self.database),
        )
        self.assertTrue(factory_gate.security_report()["production_mode"])

    def test_namespaces_are_independent_deployments(self):
        first = self.gate(
            SQLiteApprovalLedger(self.database, deployment_namespace="alpha")
        )
        second = self.gate(
            SQLiteApprovalLedger(self.database, deployment_namespace="beta")
        )
        self.assertIs(
            first.evaluate(self.proposal, approval=self.approval).verdict,
            Verdict.AUTHORIZED,
        )
        self.assertIs(
            second.evaluate(self.proposal, approval=self.approval).verdict,
            Verdict.AUTHORIZED,
        )

    def test_newer_schema_is_rejected(self):
        connection = sqlite3.connect(self.database)
        connection.execute(
            "CREATE TABLE armour_schema (component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO armour_schema(component, version) VALUES (?, ?)",
            ("approval_ledger", 999),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(ApprovalLedgerError, "newer"):
            SQLiteApprovalLedger(self.database)

    def test_ledger_file_is_owner_only(self):
        SQLiteApprovalLedger(self.database)
        mode = stat.S_IMODE(self.database.stat().st_mode)
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
