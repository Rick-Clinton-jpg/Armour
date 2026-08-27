"""Fail-closed risk aggregation and governance decisions."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from threading import Lock

from .models import ActionProposal, Decision, HumanApproval, Risk, Verdict
from .policy import Policy
from .verifiers import (
    ActionVerifier,
    DangerousContentVerifier,
    EffectVerifier,
    FilesystemVerifier,
    NetworkVerifier,
)


class ArmourGate:
    def __init__(
        self,
        policy: Policy,
        *,
        network_verifier: object | None = None,
        additional_verifiers: Iterable[object] = (),
    ):
        self.policy = policy
        # Core checks are mandatory. Callers may add checks, never replace them.
        self.verifiers = (
            ActionVerifier(),
            EffectVerifier(),
            FilesystemVerifier(),
            network_verifier or NetworkVerifier(),
            DangerousContentVerifier(),
            *tuple(additional_verifiers),
        )
        self._approval_lock = Lock()
        self._used_approval_nonces: set[str] = set()

    def evaluate(
        self,
        proposal: ActionProposal,
        *,
        request_risk: Risk = Risk.LOW,
        approval: HumanApproval | None = None,
        consume_approval: bool = False,
    ) -> Decision:
        checks = tuple(v.check(proposal, self.policy) for v in self.verifiers)
        effective_risk = max(
            (proposal.risk, request_risk, *(check.inferred_risk for check in checks))
        )
        reasons = tuple(reason for check in checks for reason in check.reasons)

        if not checks or any(not check.passed for check in checks):
            return Decision(
                proposal_id=proposal.id,
                verdict=Verdict.REJECTED,
                effective_risk=effective_risk,
                checks=checks,
                reasons=reasons,
                policy_fingerprint=self.policy.fingerprint(),
            )
        approved = False
        approval_reason = ""
        if effective_risk >= self.policy.human_gate_at:
            approved, approval_reason = self._validate_approval(proposal, approval)
            if approved and consume_approval:
                with self._approval_lock:
                    if approval.nonce in self._used_approval_nonces:
                        approved = False
                        approval_reason = "approval nonce already consumed"
                    else:
                        self._used_approval_nonces.add(approval.nonce)
        if effective_risk >= self.policy.human_gate_at and not approved:
            return Decision(
                proposal_id=proposal.id,
                verdict=Verdict.ESCALATED,
                effective_risk=effective_risk,
                checks=checks,
                reasons=reasons
                + ((approval_reason,) if approval_reason else ())
                + ("human approval required",),
                policy_fingerprint=self.policy.fingerprint(),
                human_required=True,
            )
        return Decision(
            proposal_id=proposal.id,
            verdict=Verdict.AUTHORIZED,
            effective_risk=effective_risk,
            checks=checks,
            reasons=reasons
            + ((f"human approval recorded from {approval.approved_by}",) if approved else ()),
            policy_fingerprint=self.policy.fingerprint(),
            human_required=effective_risk >= self.policy.human_gate_at,
            human_approved=approved,
            approved_by=approval.approved_by if approved else None,
            approval_nonce=approval.nonce if approved else None,
        )

    def _validate_approval(
        self, proposal: ActionProposal, approval: HumanApproval | None
    ) -> tuple[bool, str]:
        if approval is None:
            return False, ""
        if approval.proposal_id != proposal.id:
            return False, "approval is bound to a different proposal id"
        if approval.proposal_fingerprint != proposal.fingerprint():
            return False, "proposal changed after approval"
        if approval.policy_fingerprint != self.policy.fingerprint():
            return False, "policy changed after approval"
        try:
            expires = datetime.fromisoformat(approval.expires_at)
            if expires.tzinfo is None:
                return False, "approval expiry must include a timezone"
        except ValueError:
            return False, "approval expiry is invalid"
        if expires <= datetime.now(timezone.utc):
            return False, "approval has expired"
        if not approval.approved_by.strip() or not approval.nonce:
            return False, "approval identity or nonce is missing"
        with self._approval_lock:
            if approval.nonce in self._used_approval_nonces:
                return False, "approval nonce already consumed"
        return True, ""
