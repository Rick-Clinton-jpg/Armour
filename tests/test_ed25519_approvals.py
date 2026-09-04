import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from armour import (
    ActionProposal,
    ArmourGate,
    Ed25519ApprovalSigner,
    Ed25519ApprovalVerifier,
    Effect,
    Policy,
    Risk,
    SQLiteApprovalLedger,
    Verdict,
)


def private_bytes() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


class Ed25519ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.policy = Policy(
            allowed_actions=frozenset({"delete"}),
            action_effects={"delete": Effect.DESTRUCTIVE},
            policy_id="public-key-test",
        )
        self.proposal = ActionProposal("delete", Effect.DESTRUCTIVE, Risk.HIGH)
        self.signer = Ed25519ApprovalSigner("review-key-1", private_bytes())
        self.verifier = Ed25519ApprovalVerifier(
            {"review-key-1": self.signer.public_key_bytes()}
        )

    def tearDown(self):
        self.temp.cleanup()

    def approval(self):
        return self.signer.issue(
            self.proposal,
            policy_fingerprint=self.policy.fingerprint(),
            approved_by="human-reviewer",
            reason="approved test action",
        )

    def test_public_key_verifier_authorizes_valid_approval(self):
        gate = ArmourGate(self.policy, approval_verifier=self.verifier)
        self.assertIs(
            gate.evaluate(self.proposal, approval=self.approval()).verdict,
            Verdict.AUTHORIZED,
        )

    def test_tampered_approval_is_rejected(self):
        approval = replace(self.approval(), approved_by="attacker")
        gate = ArmourGate(self.policy, approval_verifier=self.verifier)
        self.assertIs(
            gate.evaluate(self.proposal, approval=approval).verdict,
            Verdict.ESCALATED,
        )

    def test_wrong_or_revoked_key_is_rejected(self):
        replacement = Ed25519ApprovalSigner("review-key-2", private_bytes())
        rotated_verifier = Ed25519ApprovalVerifier(
            {"review-key-2": replacement.public_key_bytes()}
        )
        gate = ArmourGate(self.policy, approval_verifier=rotated_verifier)
        self.assertIs(
            gate.evaluate(self.proposal, approval=self.approval()).verdict,
            Verdict.ESCALATED,
        )

    def test_rotation_window_can_trust_old_and_new_keys(self):
        replacement = Ed25519ApprovalSigner("review-key-2", private_bytes())
        verifier = Ed25519ApprovalVerifier(
            {
                "review-key-1": self.signer.public_key_bytes(),
                "review-key-2": replacement.public_key_bytes(),
            }
        )
        old_approval = self.approval()
        new_approval = replacement.issue(
            self.proposal,
            policy_fingerprint=self.policy.fingerprint(),
            approved_by="human-reviewer",
        )
        old_gate = ArmourGate(self.policy, approval_verifier=verifier)
        new_gate = ArmourGate(self.policy, approval_verifier=verifier)
        self.assertIs(
            old_gate.evaluate(self.proposal, approval=old_approval).verdict,
            Verdict.AUTHORIZED,
        )
        self.assertIs(
            new_gate.evaluate(self.proposal, approval=new_approval).verdict,
            Verdict.AUTHORIZED,
        )

    def test_malformed_signature_and_public_key_are_rejected(self):
        approval = replace(self.approval(), signature="not-hex")
        self.assertFalse(self.verifier.verify(approval))
        with self.assertRaisesRegex(ValueError, "32 raw bytes"):
            Ed25519ApprovalVerifier({"bad": b"short"})

    def test_signer_refuses_an_approval_for_another_key_id(self):
        approval = replace(self.approval(), key_id="another-key", signature="")
        with self.assertRaisesRegex(ValueError, "does not match signer"):
            self.signer.sign(approval)

    def test_production_gate_never_receives_private_key(self):
        ledger = SQLiteApprovalLedger(
            Path(self.temp.name) / "approvals.sqlite3",
            deployment_namespace="ed25519-production-test",
            integrity_key=b"approval-ledger-integrity-key!!!",
        )
        gate = ArmourGate.production(
            self.policy,
            approval_verifier=self.verifier,
            approval_ledger=ledger,
        )
        self.assertIs(
            gate.evaluate(self.proposal, approval=self.approval()).verdict,
            Verdict.AUTHORIZED,
        )
        self.assertEqual(gate.security_report()["weaknesses"], ())


if __name__ == "__main__":
    unittest.main()
