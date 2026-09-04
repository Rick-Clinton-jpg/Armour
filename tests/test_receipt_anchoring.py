import json
import tempfile
import unittest
from pathlib import Path

from armour import (
    ActionProposal,
    ArmourGate,
    Effect,
    Policy,
    ReceiptIntegrityError,
    ReceiptLog,
    Risk,
)


class ReceiptAnchoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy = Policy(
            allowed_actions=frozenset({"observe"}),
            action_effects={"observe": Effect.READ_ONLY},
        )
        self.gate = ArmourGate(self.policy)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def append(self, log: ReceiptLog, identifier: str) -> str:
        proposal = ActionProposal(
            "observe", Effect.READ_ONLY, Risk.LOW, id=identifier
        )
        return log.append(proposal, self.gate.evaluate(proposal))

    def anchored_log(self) -> ReceiptLog:
        return ReceiptLog(
            self.root / "receipts.jsonl",
            anchor_path=self.root / "receipt-checkpoints.jsonl",
        )

    def test_normal_anchored_writes_verify(self):
        log = self.anchored_log()
        first_hash = self.append(log, "first")
        second_hash = self.append(log, "second")

        verification = log.verify_anchor()
        self.assertTrue(verification)
        self.assertTrue(verification.anchoring_enabled)
        self.assertEqual(verification.primary_records, 2)
        self.assertEqual(verification.checkpoint_records, 2)
        self.assertEqual(verification.last_checkpoint_hash, second_hash)

        checkpoints = [
            json.loads(line) for line in log.anchor_path.read_text().splitlines()
        ]
        self.assertEqual(checkpoints[0]["receipt_id"], 1)
        self.assertEqual(checkpoints[0]["receipt_hash"], first_hash)
        self.assertTrue(checkpoints[0]["timestamp"])

    def test_primary_file_deletion_is_detected(self):
        log = self.anchored_log()
        self.append(log, "first")
        self.append(log, "second")
        log.path.unlink()

        verification = log.verify_anchor()
        self.assertFalse(verification)
        self.assertEqual(verification.primary_records, 0)
        self.assertEqual(verification.checkpoint_records, 2)
        self.assertIn("deleted or truncated", verification.reason)

    def test_primary_file_truncation_is_detected(self):
        log = self.anchored_log()
        self.append(log, "first")
        self.append(log, "second")
        first_line = log.path.read_text().splitlines()[0]
        log.path.write_text(first_line + "\n", encoding="utf-8")

        verification = log.verify_anchor()
        self.assertFalse(verification)
        self.assertEqual(verification.primary_records, 1)
        self.assertEqual(verification.checkpoint_records, 2)
        self.assertIn("deleted or truncated", verification.reason)

    def test_append_refuses_to_extend_a_deleted_primary_chain(self):
        log = self.anchored_log()
        self.append(log, "first")
        log.path.unlink()

        with self.assertRaisesRegex(ReceiptIntegrityError, "checkpoint"):
            self.append(log, "second")

    def test_disabled_anchoring_is_identical_to_existing_behavior(self):
        default_log = ReceiptLog(self.root / "default.jsonl")
        explicit_off_log = ReceiptLog(
            self.root / "explicit-off.jsonl", anchor_path=None
        )

        proposal = ActionProposal(
            "observe", Effect.READ_ONLY, Risk.LOW, id="same"
        )
        decision = self.gate.evaluate(proposal)
        default_hash = default_log.append(proposal, decision)
        explicit_hash = explicit_off_log.append(proposal, decision)

        self.assertEqual(default_hash, explicit_hash)
        self.assertEqual(
            default_log.path.read_bytes(), explicit_off_log.path.read_bytes()
        )
        self.assertFalse(default_log.anchoring_enabled)
        verification = default_log.verify_anchor()
        self.assertTrue(verification)
        self.assertFalse(verification.anchoring_enabled)
        self.assertEqual(verification.primary_records, 1)


if __name__ == "__main__":
    unittest.main()
