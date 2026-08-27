import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from armour import (
    ActionProposal, ArmourGate, Effect, HMACApprovalVerifier, HumanApproval,
    Policy, Risk, Verdict,
)
from armour.verifiers import NetworkVerifier


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.approval_key = b"test-approval-key"
        self.approval_verifier = HMACApprovalVerifier({"test-key": self.approval_key})
        self.policy = Policy(
            allowed_actions=frozenset({"read_file", "write_file", "fetch", "delete_file"}),
            action_effects={
                "read_file": Effect.READ_ONLY,
                "write_file": Effect.STATE_CHANGING,
                "fetch": Effect.READ_ONLY,
                "delete_file": Effect.DESTRUCTIVE,
            },
            allowed_roots=(self.root,),
            policy_id="test-policy",
        )

    def tearDown(self):
        self.temp.cleanup()

    def evaluate(self, action="read_file", effect=Effect.READ_ONLY, risk=Risk.LOW, **kwargs):
        return ArmourGate(self.policy).evaluate(ActionProposal(action, effect, risk, **kwargs))

    def approval(self, proposal, **kwargs):
        return HumanApproval.issue(
            proposal,
            policy_fingerprint=self.policy.fingerprint(),
            approved_by="test-human",
            signing_key=self.approval_key,
            key_id="test-key",
            **kwargs,
        )

    def test_unknown_action_fails_closed(self):
        self.assertIs(self.evaluate(action="invented").verdict, Verdict.REJECTED)

    def test_policy_requires_an_effect_for_every_allowed_action(self):
        with self.assertRaisesRegex(ValueError, "requires a policy-owned effect"):
            Policy(allowed_actions=frozenset({"unclassified"}))

    def test_untrusted_json_is_normalized(self):
        proposal = ActionProposal.from_untrusted({
            "action": "read_file",
            "effect": "read_only",
            "risk": "low",
            "resource": str(self.root / "a.md"),
            "payload": {},
        })
        self.assertIs(proposal.effect, Effect.READ_ONLY)
        self.assertIs(proposal.risk, Risk.LOW)

    def test_nested_payload_is_immutable_after_validation(self):
        proposal = ActionProposal.from_untrusted({
            "action": "read_file",
            "effect": "read_only",
            "risk": "low",
            "payload": {"nested": {"values": [1, 2]}},
        })
        with self.assertRaises(TypeError):
            proposal.payload["nested"]["new"] = True
        with self.assertRaises(AttributeError):
            proposal.payload["nested"]["values"].append(3)
        self.assertEqual(
            proposal.payload_data(), {"nested": {"values": [1, 2]}}
        )

    def test_approval_for_another_proposal_does_not_authorize(self):
        proposal = ActionProposal(
            "delete_file", Effect.DESTRUCTIVE, Risk.HIGH,
            resource=str(self.root / "a.md"),
        )
        other = ActionProposal("delete_file", Effect.DESTRUCTIVE, Risk.HIGH)
        decision = ArmourGate(self.policy).evaluate(
            proposal, approval=self.approval(other)
        )
        self.assertIs(decision.verdict, Verdict.ESCALATED)

    def test_read_inside_root_is_authorized(self):
        decision = self.evaluate(resource=str(self.root / "a.md"))
        self.assertIs(decision.verdict, Verdict.AUTHORIZED)

    def test_path_outside_root_is_rejected(self):
        self.assertIs(self.evaluate(resource="/etc/passwd").verdict, Verdict.REJECTED)

    def test_relative_paths_are_rejected(self):
        self.assertIs(self.evaluate(resource="notes/a.md").verdict, Verdict.REJECTED)

    def test_state_change_has_medium_risk_floor(self):
        decision = self.evaluate(
            action="write_file", effect=Effect.STATE_CHANGING, resource=str(self.root / "a.md")
        )
        self.assertIs(decision.verdict, Verdict.AUTHORIZED)
        self.assertIs(decision.effective_risk, Risk.MEDIUM)

    def test_destructive_action_escalates(self):
        decision = self.evaluate(
            action="delete_file", effect=Effect.DESTRUCTIVE, resource=str(self.root / "a.md")
        )
        self.assertIs(decision.verdict, Verdict.ESCALATED)
        self.assertTrue(decision.human_required)

    def test_human_approval_authorizes_escalated_action(self):
        proposal = ActionProposal(
            "delete_file", Effect.DESTRUCTIVE, Risk.HIGH, resource=str(self.root / "a.md")
        )
        decision = ArmourGate(
            self.policy, approval_verifier=self.approval_verifier
        ).evaluate(
            proposal, approval=self.approval(proposal)
        )
        self.assertIs(decision.verdict, Verdict.AUTHORIZED)
        self.assertTrue(decision.human_approved)

    def test_irreversible_stays_rejected_with_approval(self):
        proposal = ActionProposal("delete_file", Effect.IRREVERSIBLE, Risk.CRITICAL)
        decision = ArmourGate(self.policy).evaluate(
            proposal, approval=self.approval(proposal)
        )
        self.assertIs(decision.verdict, Verdict.REJECTED)

    def test_changed_arguments_invalidate_approval(self):
        proposal = ActionProposal(
            "delete_file", Effect.DESTRUCTIVE, Risk.HIGH,
            resource=str(self.root / "a.md"), payload={"force": False},
        )
        approval = self.approval(proposal)
        changed = ActionProposal(
            "delete_file", Effect.DESTRUCTIVE, Risk.HIGH,
            resource=str(self.root / "a.md"), payload={"force": True}, id=proposal.id,
        )
        decision = ArmourGate(self.policy).evaluate(changed, approval=approval)
        self.assertIs(decision.verdict, Verdict.ESCALATED)
        self.assertIn("proposal changed after approval", decision.reasons)

    def test_policy_revision_invalidates_approval(self):
        proposal = ActionProposal("delete_file", Effect.DESTRUCTIVE, Risk.HIGH)
        approval = self.approval(proposal)
        revised = replace(self.policy, revision=2)
        decision = ArmourGate(revised).evaluate(proposal, approval=approval)
        self.assertIs(decision.verdict, Verdict.ESCALATED)
        self.assertIn("policy changed after approval", decision.reasons)

    def test_expired_approval_is_rejected(self):
        proposal = ActionProposal("delete_file", Effect.DESTRUCTIVE, Risk.HIGH)
        approval = replace(
            self.approval(proposal),
            expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        )
        decision = ArmourGate(self.policy).evaluate(proposal, approval=approval)
        self.assertIs(decision.verdict, Verdict.ESCALATED)
        self.assertIn("approval has expired", decision.reasons)

    def test_policy_effect_overrides_model_understatement(self):
        proposal = ActionProposal("delete_file", Effect.READ_ONLY, Risk.LOW)
        decision = ArmourGate(self.policy).evaluate(proposal)
        self.assertIs(decision.verdict, Verdict.ESCALATED)
        self.assertIs(decision.effective_risk, Risk.HIGH)

    def test_request_risk_cannot_be_lowered_by_candidate(self):
        proposal = ActionProposal(
            "read_file", Effect.READ_ONLY, Risk.LOW, resource=str(self.root / "a")
        )
        decision = ArmourGate(self.policy).evaluate(proposal, request_risk=Risk.HIGH)
        self.assertIs(decision.verdict, Verdict.ESCALATED)
        self.assertIs(decision.effective_risk, Risk.HIGH)

    def test_private_network_is_rejected_after_resolution(self):
        verifier = NetworkVerifier(resolver=lambda host: ["127.0.0.1"])
        proposal = ActionProposal("fetch", Effect.READ_ONLY, Risk.LOW, resource="https://x.test/a")
        decision = ArmourGate(self.policy, network_verifier=verifier).evaluate(proposal)
        self.assertIs(decision.verdict, Verdict.REJECTED)

    def test_public_get_is_authorized(self):
        verifier = NetworkVerifier(resolver=lambda host: ["93.184.216.34"])
        proposal = ActionProposal("fetch", Effect.READ_ONLY, Risk.LOW, resource="https://example.com/a")
        decision = ArmourGate(self.policy, network_verifier=verifier).evaluate(proposal)
        self.assertIs(decision.verdict, Verdict.AUTHORIZED)

    def test_network_write_is_rejected(self):
        verifier = NetworkVerifier(resolver=lambda host: ["93.184.216.34"])
        proposal = ActionProposal(
            "fetch", Effect.STATE_CHANGING, Risk.MEDIUM,
            resource="https://example.com/a", method="POST",
        )
        decision = ArmourGate(self.policy, network_verifier=verifier).evaluate(proposal)
        self.assertIs(decision.verdict, Verdict.REJECTED)


if __name__ == "__main__":
    unittest.main()
