import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from armour import (
    ActionProposal,
    ArmourGate,
    BoundaryMutation,
    BoundaryProbeResult,
    Effect,
    Mutation,
    MutationRunner,
    Policy,
    Risk,
    STANDARD_INVARIANTS,
    Verdict,
    standard_mutant_family,
)


class MutationEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy = Policy(
            allowed_actions=frozenset({"read_file", "delete_file"}),
            action_effects={
                "read_file": Effect.READ_ONLY,
                "delete_file": Effect.DESTRUCTIVE,
            },
            allowed_roots=(self.root,),
        )
        self.baseline = ActionProposal(
            "read_file", Effect.READ_ONLY, Risk.LOW,
            resource=str(self.root / "note.md"),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_standard_family_exercises_and_kills_every_required_invariant(self):
        gate = ArmourGate(self.policy)
        report = MutationRunner(
            gate, required_invariants=STANDARD_INVARIANTS
        ).run(self.baseline, standard_mutant_family(self.baseline, self.policy))
        self.assertTrue(report.passed)
        self.assertEqual(report.mutation_score, 1.0)
        self.assertEqual(report.invariant_coverage, 1.0)
        self.assertFalse(report.surviving_mutants)

    def test_surviving_mutant_is_reported(self):
        mutation = Mutation(
            "cosmetic-change",
            "a mutation deliberately expected to be rejected but still safe",
            "custom_invariant",
            lambda proposal: ActionProposal(
                proposal.action,
                proposal.effect,
                proposal.risk,
                resource=proposal.resource,
                payload={"cosmetic": True},
                id=proposal.id,
            ),
            frozenset({Verdict.REJECTED}),
        )
        report = MutationRunner(
            ArmourGate(self.policy), required_invariants={"custom_invariant"}
        ).run(self.baseline, [mutation])
        self.assertFalse(report.passed)
        self.assertEqual(report.mutation_score, 0.0)
        self.assertEqual(report.surviving_mutants[0].mutation_id, "cosmetic-change")

    def test_uncovered_invariant_fails_report(self):
        report = MutationRunner(
            ArmourGate(self.policy),
            required_invariants={"action_allowlist", "missing_invariant"},
        ).run(
            self.baseline,
            [standard_mutant_family(self.baseline, self.policy)[0]],
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.uncovered_invariants, frozenset({"missing_invariant"}))

    def test_expanded_security_invariants_are_present_and_covered(self):
        expanded = {
            "production_isolated_signing",
            "production_durable_ledger",
            "production_ledger_integrity",
            "approval_ledger_row_integrity",
            "approval_ledger_nonce_durability",
            "approval_ledger_rollback_detection",
            "approval_ledger_key_integrity",
            "network_destination_binding",
            "network_public_destination",
            "network_method_binding",
            "security_memory_integrity",
            "security_memory_quarantine",
            "security_memory_review_gate",
        }
        self.assertTrue(expanded <= STANDARD_INVARIANTS)
        report = MutationRunner(
            ArmourGate(self.policy), required_invariants=STANDARD_INVARIANTS
        ).run(self.baseline, standard_mutant_family(self.baseline, self.policy))
        self.assertTrue(expanded <= report.exercised_invariants)
        self.assertEqual(report.invariant_coverage, 1.0)

    def test_unexpected_boundary_probe_failure_is_a_surviving_mutant(self):
        def broken_probe(_gate, _baseline):
            raise RuntimeError("probe itself broke")

        mutation = BoundaryMutation(
            "broken-boundary-probe",
            "a broken probe must not count as protection",
            "boundary_probe_integrity",
            broken_probe,
            frozenset({Verdict.REJECTED}),
        )
        report = MutationRunner(
            ArmourGate(self.policy),
            required_invariants={"boundary_probe_integrity"},
        ).run(self.baseline, [mutation])
        self.assertFalse(report.passed)
        self.assertEqual(report.mutation_score, 0.0)
        self.assertIs(report.outcomes[0].verdict, Verdict.AUTHORIZED)

    def test_boundary_survivor_fails_the_report(self):
        mutation = BoundaryMutation(
            "accepted-boundary-attack",
            "simulate a boundary that accepted the attack",
            "boundary_rejection",
            lambda _gate, _baseline: BoundaryProbeResult(
                Verdict.AUTHORIZED, ("accepted",)
            ),
            frozenset({Verdict.REJECTED}),
        )
        report = MutationRunner(
            ArmourGate(self.policy), required_invariants={"boundary_rejection"}
        ).run(self.baseline, [mutation])
        self.assertFalse(report.passed)
        self.assertEqual(
            report.surviving_mutants[0].mutation_id,
            "accepted-boundary-attack",
        )

    def test_runner_never_calls_the_real_executor(self):
        with patch(
            "armour.executor.GuardedExecutor.execute",
            side_effect=AssertionError("mutation runner executed a handler"),
        ) as execute:
            report = MutationRunner(
                ArmourGate(self.policy), required_invariants=STANDARD_INVARIANTS
            ).run(
                self.baseline,
                standard_mutant_family(self.baseline, self.policy),
            )
        self.assertTrue(report.passed)
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
