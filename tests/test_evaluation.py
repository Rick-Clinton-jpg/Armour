import tempfile
import unittest
from pathlib import Path

from armour import (
    ActionProposal,
    ArmourGate,
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


if __name__ == "__main__":
    unittest.main()
