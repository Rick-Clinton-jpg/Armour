import gc
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
import warnings
from contextlib import closing
from pathlib import Path

from armour import (
    ActionProposal,
    ArmourGate,
    Effect,
    Policy,
    RememberingGate,
    Risk,
    SecurityMemoryError,
    SecurityMemorySandbox,
    SQLiteIncidentMemory,
    SQLiteMutantMemory,
    Verdict,
)


class WallClock:
    def __init__(self):
        self.now = 10_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TrustedCheckpoint:
    def __init__(self):
        self.generations = {}
        self.lock = threading.Lock()

    def read_generation(self, component, namespace):
        with self.lock:
            return self.generations.get((component, namespace))

    def advance_generation(self, component, namespace, generation):
        with self.lock:
            key = (component, namespace)
            current = self.generations.get(key, -1)
            self.generations[key] = max(current, generation)


class SecurityMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.outside = self.base / "outside"
        self.root.mkdir()
        self.outside.mkdir()
        self.safe = self.root / "safe.txt"
        self.secret = self.outside / "secret.txt"
        self.safe.write_text("safe")
        self.secret.write_text("secret")
        self.db = self.base / "memory.sqlite3"
        self.clock = WallClock()
        self.integrity_key = b"security-memory-test-key-material!"
        self.policy = Policy(
            allowed_actions=frozenset({"read"}),
            action_effects={"read": Effect.READ_ONLY},
            allowed_roots=(self.root,),
            policy_id="memory-tests",
        )
        self.safe_proposal = ActionProposal(
            "read", Effect.READ_ONLY, Risk.LOW, resource=str(self.safe)
        )
        self.attack = ActionProposal(
            "read", Effect.READ_ONLY, Risk.LOW, resource=str(self.secret)
        )

    def tearDown(self):
        self.temp.cleanup()

    def incident_memory(self):
        return SQLiteIncidentMemory(
            self.db, deployment_namespace="tests", wall_clock=self.clock,
            integrity_key=self.integrity_key,
        )

    def mutant_memory(self):
        return SQLiteMutantMemory(
            self.db, deployment_namespace="tests", wall_clock=self.clock,
            integrity_key=self.integrity_key,
        )

    def remembering_gate(self, threshold=3, window=300):
        return RememberingGate(
            ArmourGate(self.policy),
            self.incident_memory(),
            rejection_threshold=threshold,
            window_seconds=window,
            wall_clock=self.clock,
        )

    def test_rejection_is_remembered_with_verifier_derived_family(self):
        gate = self.remembering_gate()
        decision = gate.evaluate(self.attack, subject_id="agent-a")
        self.assertIs(decision.verdict, Verdict.REJECTED)
        incident = gate.incident_memory.incidents("agent-a")[0]
        self.assertEqual(incident.families, ("filesystem_scope",))
        self.assertEqual(incident.policy_fingerprint, self.policy.fingerprint())

    def test_memory_survives_new_store_and_gate_instances(self):
        self.remembering_gate().evaluate(self.attack, subject_id="agent-a")
        restarted = self.remembering_gate()
        self.assertEqual(
            restarted.incident_memory.rejection_count("agent-a", since=0), 1
        )

    def test_exact_same_attack_is_counted_again(self):
        gate = self.remembering_gate()
        gate.evaluate(self.attack, subject_id="agent-a")
        gate.evaluate(self.attack, subject_id="agent-a")
        self.assertEqual(
            gate.incident_memory.rejection_count("agent-a", since=0), 2
        )

    def test_repeated_rejections_quarantine_future_safe_action(self):
        gate = self.remembering_gate(threshold=3)
        for index in range(3):
            decision = gate.evaluate(
                ActionProposal(
                    "read", Effect.READ_ONLY, Risk.LOW,
                    resource=str(self.secret), id=f"attack-{index}",
                ),
                subject_id="agent-a",
            )
            self.assertIs(decision.verdict, Verdict.REJECTED)
        restarted = self.remembering_gate(threshold=3)
        decision = restarted.evaluate(self.safe_proposal, subject_id="agent-a")
        self.assertIs(decision.verdict, Verdict.REJECTED)
        self.assertTrue(any("quarantined" in reason for reason in decision.reasons))

    def test_quarantine_is_scoped_to_trusted_subject(self):
        gate = self.remembering_gate(threshold=1)
        gate.evaluate(self.attack, subject_id="agent-a")
        self.assertIs(
            gate.evaluate(self.safe_proposal, subject_id="agent-b").verdict,
            Verdict.AUTHORIZED,
        )

    def test_old_incidents_age_out_of_the_active_window(self):
        gate = self.remembering_gate(threshold=1, window=10)
        gate.evaluate(self.attack, subject_id="agent-a")
        self.clock.advance(11)
        self.assertIs(
            gate.evaluate(self.safe_proposal, subject_id="agent-a").verdict,
            Verdict.AUTHORIZED,
        )

    def test_incident_memory_does_not_record_authorized_actions(self):
        gate = self.remembering_gate()
        gate.evaluate(self.safe_proposal, subject_id="agent-a")
        self.assertEqual(gate.incident_memory.incidents(), ())

    def test_untrusted_empty_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            self.remembering_gate().evaluate(self.attack, subject_id="")

    def test_memory_file_is_owner_only(self):
        self.incident_memory()
        self.assertEqual(os.stat(self.db).st_mode & 0o777, 0o600)

    def test_incident_does_not_auto_promote_into_mutant_memory(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        sandbox.observe("agent-a", self.attack)
        self.assertEqual(sandbox.mutant_memory.mutants(), ())

    def test_reviewed_mutant_survives_restart_and_replays(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        sandbox.observe("agent-a", self.attack)
        remembered = sandbox.promote(
            "outside-root", self.attack, promoted_by="security-reviewer"
        )
        self.assertIsNotNone(remembered.source_incident_id)
        restarted = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        report = restarted.replay()
        self.assertTrue(report.passed)
        self.assertEqual(report.outcomes[0].name, "outside-root")

    def test_unobserved_proposal_cannot_be_promoted(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        with self.assertRaisesRegex(ValueError, "observed rejection"):
            sandbox.promote("invented", self.attack, promoted_by="reviewer")

    def test_remembered_mutant_detects_policy_regression(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        sandbox.observe("agent-a", self.attack)
        sandbox.promote("outside-root", self.attack, promoted_by="reviewer")
        weakened = Policy(
            allowed_actions=frozenset({"read"}),
            action_effects={"read": Effect.READ_ONLY},
            allowed_roots=(self.base,),
            policy_id="weakened",
        )
        report = sandbox.replay(ArmourGate(weakened))
        self.assertFalse(report.passed)
        self.assertEqual(report.survivors[0].name, "outside-root")
        self.assertIs(report.survivors[0].verdict, Verdict.AUTHORIZED)

    def test_mutant_memory_is_data_only(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        sandbox.observe("agent-a", self.attack)
        sandbox.promote("outside-root", self.attack, promoted_by="reviewer")
        with closing(sqlite3.connect(self.db)) as connection:
            stored = connection.execute(
                "SELECT proposal_json FROM remembered_mutants"
            ).fetchone()[0]
        self.assertIn('"action":"read"', stored)
        self.assertNotIn("lambda", stored)

    def test_duplicate_mutant_name_is_rejected(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        sandbox.observe("agent-a", self.attack)
        sandbox.promote("outside-root", self.attack, promoted_by="reviewer")
        with self.assertRaisesRegex(ValueError, "already exists"):
            sandbox.promote("outside-root", self.attack, promoted_by="reviewer")

    def test_same_proposal_cannot_fill_mutant_memory_under_aliases(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        sandbox.observe("agent-a", self.attack)
        sandbox.promote("first-name", self.attack, promoted_by="reviewer")
        with self.assertRaisesRegex(ValueError, "proposal already exists"):
            sandbox.promote("second-name", self.attack, promoted_by="reviewer")

    def test_initial_mutant_schema_migrates_and_collapses_exact_aliases(self):
        proposal_json = json.dumps(
            {
                "id": self.attack.id,
                "action": self.attack.action,
                "effect": self.attack.effect.value,
                "risk": self.attack.risk.name.lower(),
                "resource": self.attack.resource,
                "method": self.attack.method,
                "payload": self.attack.payload_data(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute(
                """
                CREATE TABLE armour_schema (
                    component TEXT PRIMARY KEY, version INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO armour_schema VALUES ('mutant_memory', 1)"
            )
            connection.execute(
                """
                CREATE TABLE remembered_mutants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_namespace TEXT NOT NULL,
                    name TEXT NOT NULL,
                    proposal_json TEXT NOT NULL,
                    expected_verdicts_json TEXT NOT NULL,
                    policy_fingerprint TEXT NOT NULL,
                    promoted_by TEXT NOT NULL,
                    source_incident_id INTEGER,
                    created_at REAL NOT NULL,
                    UNIQUE (deployment_namespace, name)
                )
                """
            )
            for name in ("first", "alias"):
                connection.execute(
                    """
                    INSERT INTO remembered_mutants (
                        deployment_namespace, name, proposal_json,
                        expected_verdicts_json, policy_fingerprint, promoted_by,
                        source_incident_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "tests", name, proposal_json, '["rejected"]',
                        self.policy.fingerprint(), "reviewer", None, self.clock(),
                    ),
                )
            connection.commit()
        with self.assertRaisesRegex(SecurityMemoryError, "unsealed"):
            SQLiteMutantMemory(
                self.db, deployment_namespace="tests", wall_clock=self.clock,
                integrity_key=self.integrity_key,
            )
        memory = SQLiteMutantMemory(
            self.db, deployment_namespace="tests", wall_clock=self.clock,
            integrity_key=self.integrity_key, trust_existing_records=True,
        )
        self.assertEqual([mutant.name for mutant in memory.mutants()], ["first"])
        with closing(sqlite3.connect(self.db)) as connection:
            version = connection.execute(
                "SELECT version FROM armour_schema WHERE component = 'mutant_memory'"
            ).fetchone()[0]
        self.assertEqual(version, 2)

    def test_incident_memory_retains_bounded_recent_history(self):
        memory = SQLiteIncidentMemory(
            self.db,
            deployment_namespace="bounded",
            wall_clock=self.clock,
            max_records_per_subject=3,
            max_records_total=4,
            integrity_key=self.integrity_key,
        )
        for index in range(5):
            proposal = ActionProposal(
                "read", Effect.READ_ONLY, Risk.LOW,
                resource=str(self.secret), id=f"bounded-{index}",
            )
            memory.record_rejection(
                "agent-a",
                proposal,
                ArmourGate(self.policy).evaluate(proposal),
            )
        self.assertEqual(len(memory.incidents("agent-a")), 3)

    def test_total_capacity_cannot_evict_another_subject_history(self):
        memory = SQLiteIncidentMemory(
            self.db,
            deployment_namespace="total-capacity",
            wall_clock=self.clock,
            max_records_per_subject=2,
            max_records_total=2,
            integrity_key=self.integrity_key,
        )
        decision = ArmourGate(self.policy).evaluate(self.attack)
        memory.record_rejection("agent-a", self.attack, decision)
        second = ActionProposal(
            "read", Effect.READ_ONLY, Risk.LOW,
            resource=str(self.secret), id="second-a",
        )
        memory.record_rejection(
            "agent-a", second, ArmourGate(self.policy).evaluate(second)
        )
        with self.assertRaisesRegex(SecurityMemoryError, "capacity"):
            memory.record_rejection("agent-b", self.attack, decision)
        self.assertEqual(len(memory.incidents("agent-a")), 2)

    def test_incident_rejects_decision_for_different_proposal(self):
        memory = SQLiteIncidentMemory(
            self.db, deployment_namespace="mismatch",
            integrity_key=self.integrity_key,
        )
        decision = ArmourGate(self.policy).evaluate(self.attack)
        other = ActionProposal(
            "read", Effect.READ_ONLY, Risk.LOW,
            resource=str(self.secret), id="different-proposal",
        )
        with self.assertRaisesRegex(ValueError, "identifiers must match"):
            memory.record_rejection("agent-a", other, decision)

    def test_quarantine_threshold_cannot_exceed_retained_history(self):
        memory = SQLiteIncidentMemory(
            self.db,
            deployment_namespace="threshold",
            max_records_per_subject=2,
            max_records_total=10,
            integrity_key=self.integrity_key,
        )
        with self.assertRaisesRegex(ValueError, "retention"):
            RememberingGate(
                ArmourGate(self.policy), memory, rejection_threshold=3
            )

    def test_mutant_memory_refuses_writes_at_capacity(self):
        memory = SQLiteMutantMemory(
            self.db,
            deployment_namespace="capacity",
            wall_clock=self.clock,
            max_mutants=2,
            integrity_key=self.integrity_key,
        )
        for index in range(2):
            memory.remember(
                f"mutant-{index}",
                ActionProposal(
                    "read", Effect.READ_ONLY, Risk.LOW,
                    resource=str(self.secret), id=f"capacity-{index}",
                ),
                expected_verdicts=frozenset({Verdict.REJECTED}),
                policy_fingerprint=self.policy.fingerprint(),
                promoted_by="reviewer",
            )
        with self.assertRaisesRegex(ValueError, "capacity"):
            memory.remember(
                "mutant-3",
                ActionProposal(
                    "read", Effect.READ_ONLY, Risk.LOW,
                    resource=str(self.secret), id="capacity-3",
                ),
                expected_verdicts=frozenset({Verdict.REJECTED}),
                policy_fingerprint=self.policy.fingerprint(),
                promoted_by="reviewer",
            )

    def test_corrupt_database_fails_without_leaking_connection(self):
        gate = self.remembering_gate()
        gate.evaluate(self.attack, subject_id="agent-a")
        self.db.write_bytes(b"not a sqlite database")
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", ResourceWarning)
            with self.assertRaises(Exception):
                gate.evaluate(self.safe_proposal, subject_id="agent-a")
            gc.collect()
        self.assertFalse(
            [item for item in captured if issubclass(item.category, ResourceWarning)]
        )

    def test_incident_row_tampering_fails_closed(self):
        gate = self.remembering_gate()
        gate.evaluate(self.attack, subject_id="agent-a")
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute(
                "UPDATE security_incidents SET subject_id = 'attacker'"
            )
            connection.commit()
        with self.assertRaisesRegex(SecurityMemoryError, "integrity"):
            gate.evaluate(self.safe_proposal, subject_id="agent-a")

    def test_mutant_row_tampering_fails_closed(self):
        sandbox = SecurityMemorySandbox(self.remembering_gate(), self.mutant_memory())
        sandbox.observe("agent-a", self.attack)
        sandbox.promote("outside-root", self.attack, promoted_by="reviewer")
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute(
                "UPDATE remembered_mutants SET expected_verdicts_json = '[\"authorized\"]'"
            )
            connection.commit()
        with self.assertRaisesRegex(SecurityMemoryError, "integrity"):
            sandbox.replay()

    def test_wrong_integrity_key_fails_closed(self):
        self.remembering_gate().evaluate(self.attack, subject_id="agent-a")
        with self.assertRaisesRegex(SecurityMemoryError, "integrity"):
            SQLiteIncidentMemory(
                self.db, deployment_namespace="tests",
                integrity_key=b"a-different-32-byte-integrity-key!",
            )

    def test_deleted_integrity_seal_is_not_silently_recreated(self):
        memory = self.incident_memory()
        proposal = ActionProposal(
            "read", Effect.READ_ONLY, Risk.LOW,
            resource=str(self.secret), id="sealed-incident",
        )
        memory.record_rejection(
            "agent-a", proposal, ArmourGate(self.policy).evaluate(proposal)
        )
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute(
                """
                DELETE FROM security_memory_integrity
                WHERE component = 'incident_memory'
                  AND deployment_namespace = 'tests'
                """
            )
            connection.commit()
        with self.assertRaisesRegex(SecurityMemoryError, "unsealed"):
            memory.incidents()

    def test_external_checkpoint_detects_valid_database_rollback(self):
        checkpoint = TrustedCheckpoint()
        memory = SQLiteIncidentMemory(
            self.db, deployment_namespace="anchored", wall_clock=self.clock,
            integrity_key=self.integrity_key, checkpoint=checkpoint,
        )
        first = ActionProposal(
            "read", Effect.READ_ONLY, Risk.LOW,
            resource=str(self.secret), id="rollback-first",
        )
        memory.record_rejection(
            "agent-a", first, ArmourGate(self.policy).evaluate(first)
        )
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        snapshot = self.base / "valid-old-memory.sqlite3"
        shutil.copyfile(self.db, snapshot)
        second = ActionProposal(
            "read", Effect.READ_ONLY, Risk.LOW,
            resource=str(self.secret), id="rollback-second",
        )
        memory.record_rejection(
            "agent-a", second, ArmourGate(self.policy).evaluate(second)
        )
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copyfile(snapshot, self.db)
        with self.assertRaisesRegex(SecurityMemoryError, "rollback"):
            SQLiteIncidentMemory(
                self.db, deployment_namespace="anchored",
                integrity_key=self.integrity_key, checkpoint=checkpoint,
            )

    def test_concurrent_writers_keep_checkpoint_monotonic(self):
        checkpoint = TrustedCheckpoint()
        memory = SQLiteIncidentMemory(
            self.db, deployment_namespace="concurrent-anchor",
            integrity_key=self.integrity_key, checkpoint=checkpoint,
        )
        decision = ArmourGate(self.policy).evaluate(self.attack)
        errors = []

        def write_incident():
            try:
                memory.record_rejection("agent-a", self.attack, decision)
            except Exception as exc:  # captured for assertion across the thread
                errors.append(exc)

        threads = [threading.Thread(target=write_incident) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(memory.rejection_count("agent-a", since=0), 16)
        self.assertEqual(
            checkpoint.read_generation("incident_memory", "concurrent-anchor"),
            16,
        )

    def test_remembering_gate_rejects_unprotected_memory(self):
        memory = SQLiteIncidentMemory(
            self.db, deployment_namespace="unprotected"
        )
        with self.assertRaisesRegex(ValueError, "integrity-protected"):
            RememberingGate(ArmourGate(self.policy), memory)


if __name__ == "__main__":
    unittest.main()
