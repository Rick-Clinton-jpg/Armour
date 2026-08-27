"""Fail-closed risk aggregation and governance decisions."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
import logging
from threading import Lock

from .approvals import ApprovalVerifier
from .models import ActionProposal, CheckResult, Decision, HumanApproval, Risk, Verdict
from .policy import Policy
from .verifiers import (
    ActionVerifier,
    DangerousContentVerifier,
    EffectVerifier,
    FilesystemVerifier,
    NetworkVerifier,
    SchemaVerifier,
)


logger = logging.getLogger(__name__)


class ArmourGate:
    def __init__(
        self,
        policy: Policy,
        *,
        network_verifier: object | None = None,
        additional_verifiers: Iterable[object] = (),
        approval_verifier: ApprovalVerifier | None = None,
    ):
        self.policy = policy
        self.approval_verifier = approval_verifier
        # Core checks are mandatory. Callers may add checks, never replace them.
        self.verifiers = (
            ActionVerifier(),
            SchemaVerifier(),
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
        checks: list[CheckResult] = []
        try:
            policy_fingerprint = self.policy.fingerprint()
        except Exception:
            logger.exception("policy integrity verification raised")
            policy_fingerprint = ""
            checks.append(
                CheckResult(
                    "policy_integrity",
                    False,
                    ("policy integrity verification failed",),
                    Risk.CRITICAL,
                )
            )
        for verifier in self.verifiers:
            try:
                result = verifier.check(proposal, self.policy)
                if not isinstance(result, CheckResult):
                    raise TypeError("verifier did not return CheckResult")
                checks.append(result)
            except Exception:
                name = getattr(verifier, "name", type(verifier).__name__)
                logger.exception("verifier %s raised", name)
                checks.append(
                    CheckResult(
                        str(name),
                        False,
                        (f"verifier_error:{name}",),
                        Risk.CRITICAL,
                    )
                )
        if policy_fingerprint:
            try:
                self.policy.fingerprint()
            except Exception:
                logger.exception("policy changed during evaluation")
                checks.append(
                    CheckResult(
                        "policy_integrity",
                        False,
                        ("policy changed during evaluation",),
                        Risk.CRITICAL,
                    )
                )
        check_results = tuple(checks)
        effective_risk = max(
            (
                proposal.risk,
                request_risk,
                *(check.inferred_risk for check in check_results),
            )
        )
        reasons = tuple(reason for check in check_results for reason in check.reasons)

        if not check_results or any(not check.passed for check in check_results):
            return Decision(
                proposal_id=proposal.id,
                verdict=Verdict.REJECTED,
                effective_risk=effective_risk,
                checks=check_results,
                reasons=reasons,
                policy_fingerprint=policy_fingerprint,
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
                checks=check_results,
                reasons=reasons
                + ((approval_reason,) if approval_reason else ())
                + ("human approval required",),
                policy_fingerprint=policy_fingerprint,
                human_required=True,
            )
        return Decision(
            proposal_id=proposal.id,
            verdict=Verdict.AUTHORIZED,
            effective_risk=effective_risk,
            checks=check_results,
            reasons=reasons
            + ((f"human approval recorded from {approval.approved_by}",) if approved else ()),
            policy_fingerprint=policy_fingerprint,
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
        if not isinstance(approval, HumanApproval):
            return False, "approval envelope is malformed"
        if approval.proposal_id != proposal.id:
            return False, "approval is bound to a different proposal id"
        if approval.proposal_fingerprint != proposal.fingerprint():
            return False, "proposal changed after approval"
        if approval.policy_fingerprint != self.policy.fingerprint():
            return False, "policy changed after approval"
        if not all(
            isinstance(value, str)
            for value in (
                approval.proposal_id,
                approval.proposal_fingerprint,
                approval.policy_fingerprint,
                approval.approved_by,
                approval.expires_at,
                approval.nonce,
                approval.key_id,
                approval.signature,
            )
        ):
            return False, "approval envelope is malformed"
        try:
            expires = datetime.fromisoformat(approval.expires_at)
            if expires.tzinfo is None:
                return False, "approval expiry must include a timezone"
        except (TypeError, ValueError):
            return False, "approval expiry is invalid"
        if expires <= datetime.now(timezone.utc):
            return False, "approval has expired"
        if not approval.approved_by.strip() or not approval.nonce:
            return False, "approval identity or nonce is missing"
        if self.approval_verifier is None:
            return False, "trusted approval verifier is not configured"
        try:
            trusted = self.approval_verifier.verify(approval)
        except Exception:
            logger.exception("approval provenance verifier raised")
            return False, "approval provenance verification failed"
        if not trusted:
            return False, "approval signature is not trusted"
        with self._approval_lock:
            if approval.nonce in self._used_approval_nonces:
                return False, "approval nonce already consumed"
        return True, ""
