import json
import tempfile
import unittest
from pathlib import Path

from armour import (
    ActionProposal, ArmourGate, Effect, GuardedExecutor, HumanApproval,
    Policy, ReceiptLog, Risk,
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
        self.assertTrue(log.verify())
        record = json.loads(log.path.read_text().splitlines()[0])
        self.assertEqual(record["decision"]["verdict"], "authorized")

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
        executor = GuardedExecutor(ArmourGate(policy), log)
        executor.register("delete", lambda proposal: "done")
        proposal = ActionProposal("delete", Effect.READ_ONLY, Risk.LOW)
        approval = HumanApproval.issue(
            proposal,
            policy_fingerprint=policy.fingerprint(),
            approved_by="test-human",
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
