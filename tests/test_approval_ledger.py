import hashlib
import hmac
import shutil
import sqlite3
import stat
import tempfile
import threading
import unittest
from contextlib import closing
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
        self.integrity_key = b"i" * 32
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

    def test_two_integrity_protected_ledgers_remain_consistent(self):
        ledgers = [
            SQLiteApprovalLedger(
                self.database, integrity_key=self.integrity_key
            ),
            SQLiteApprovalLedger(
                self.database, integrity_key=self.integrity_key
            ),
        ]
        barrier = threading.Barrier(2)
        results = []
        result_lock = threading.Lock()

        def claim(ledger):
            barrier.wait()
            claimed = ledger.claim(self.approval)
            with result_lock:
                results.append(claimed)

        threads = [threading.Thread(target=claim, args=(ledger,)) for ledger in ledgers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(results, [True, False])
        self.assertEqual(len(ledgers[0].claims()), 1)

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
        with self.assertRaisesRegex(ValueError, "isolated from the evaluator"):
            self.gate(
                SQLiteApprovalLedger(
                    self.database, integrity_key=b"x" * 32
                ),
                production_mode=True,
            )

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

    def test_direct_claim_tampering_fails_closed(self):
        ledger = SQLiteApprovalLedger(
            self.database, integrity_key=self.integrity_key
        )
        self.assertTrue(ledger.claim(self.approval))
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE approval_claims SET nonce = 'attacker-rewrite'"
            )
            connection.commit()
        with self.assertRaisesRegex(ApprovalLedgerError, "integrity"):
            ledger.claims()

    def test_wrong_ledger_integrity_key_fails_closed(self):
        ledger = SQLiteApprovalLedger(
            self.database, integrity_key=self.integrity_key
        )
        self.assertTrue(ledger.claim(self.approval))
        with self.assertRaisesRegex(ApprovalLedgerError, "integrity"):
            SQLiteApprovalLedger(
                self.database, integrity_key=b"different-key-material".ljust(32, b"!")
            )

    def test_integrity_protected_ledger_has_a_hard_capacity(self):
        ledger = SQLiteApprovalLedger(
            self.database,
            integrity_key=self.integrity_key,
            max_claims=1,
        )
        self.assertTrue(ledger.claim(self.approval))
        self.assertFalse(ledger.claim(self.approval))
        second = replace(self.approval, nonce="second-capacity-test-nonce")
        with self.assertRaisesRegex(ApprovalLedgerError, "capacity"):
            ledger.claim(second)

        with self.assertRaisesRegex(ValueError, "at most"):
            SQLiteApprovalLedger(
                Path(self.temp.name) / "excessive-capacity.sqlite3",
                max_claims=100_001,
            )

    def test_existing_claims_require_explicit_one_time_sealing(self):
        legacy = SQLiteApprovalLedger(self.database)
        self.assertTrue(legacy.claim(self.approval))
        with self.assertRaisesRegex(ApprovalLedgerError, "unsealed"):
            SQLiteApprovalLedger(
                self.database, integrity_key=self.integrity_key
            )
        sealed = SQLiteApprovalLedger(
            self.database,
            integrity_key=self.integrity_key,
            trust_existing_claims=True,
        )
        self.assertEqual(len(sealed.claims()), 1)
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DELETE FROM approval_ledger_integrity")
            connection.commit()
        with self.assertRaisesRegex(ApprovalLedgerError, "unsealed"):
            sealed.claims()

    def test_checkpoint_detects_valid_ledger_rollback(self):
        class Checkpoint:
            def __init__(self):
                self.generation = None

            def read_generation(self, _namespace):
                return self.generation

            def advance_generation(self, _namespace, generation):
                current = -1 if self.generation is None else self.generation
                self.generation = max(current, generation)

        checkpoint = Checkpoint()
        ledger = SQLiteApprovalLedger(
            self.database,
            integrity_key=self.integrity_key,
            checkpoint=checkpoint,
        )
        self.assertTrue(ledger.claim(self.approval))
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        snapshot = Path(self.temp.name) / "old-valid-ledger.sqlite3"
        shutil.copyfile(self.database, snapshot)
        another = replace(self.approval, nonce="second-valid-nonce")
        another = self.resign(replace(another, signature=""))
        self.assertTrue(ledger.claim(another))
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copyfile(snapshot, self.database)
        with self.assertRaisesRegex(ApprovalLedgerError, "rollback"):
            SQLiteApprovalLedger(
                self.database,
                integrity_key=self.integrity_key,
                checkpoint=checkpoint,
            )


if __name__ == "__main__":
    unittest.main()
