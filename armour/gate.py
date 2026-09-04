"""Fail-closed risk aggregation and governance decisions."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
import logging

from .approvals import ApprovalVerifier
from .ledger import (
    ApprovalLedger,
    InMemoryApprovalLedger,
)
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
        approval_ledger: ApprovalLedger | None = None,
        production_mode: bool = False,
    ):
        self.policy = policy
        self.approval_verifier = approval_verifier
        self.approval_ledger = (
            approval_ledger
            if approval_ledger is not None
            else InMemoryApprovalLedger()
        )
        if not isinstance(getattr(self.approval_ledger, "durable", None), bool):
            raise TypeError("approval ledger must declare whether it is durable")
        self.production_mode = production_mode
        if production_mode and approval_verifier is None:
            raise ValueError("production mode requires a trusted approval verifier")
        if production_mode and not self.approval_ledger.durable:
            raise ValueError("production mode requires a durable approval ledger")
        if production_mode and not getattr(
            approval_verifier, "signing_authority_isolated", False
        ):
            raise ValueError(
                "production mode requires approval signing authority "
                "isolated from the evaluator"
            )
        if production_mode and not getattr(
            self.approval_ledger, "integrity_protected", False
        ):
            raise ValueError(
                "production mode requires an integrity-protected approval ledger"
            )
        if approval_verifier is not None and not self.approval_ledger.durable:
            logger.warning(
                "signed approvals are using process-local replay protection; "
                "configure a durable ledger or production mode"
            )
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

    @classmethod
    def production(
        cls,
        policy: Policy,
        *,
        approval_verifier: ApprovalVerifier,
        approval_ledger: ApprovalLedger,
        **kwargs: object,
    ) -> "ArmourGate":
        """Construct a gate that refuses development-only approval controls."""
        return cls(
            policy,
            approval_verifier=approval_verifier,
            approval_ledger=approval_ledger,
            production_mode=True,
            **kwargs,
        )

    def security_report(self) -> dict[str, object]:
        """Describe the protections actually active for this gate."""
        weaknesses: list[str] = []
        if self.approval_verifier is None:
            weaknesses.append("trusted approval verifier is not configured")
        if not self.approval_ledger.durable:
            weaknesses.append("approval replay protection is process-local")
        if self.approval_verifier is not None and not getattr(
            self.approval_verifier, "signing_authority_isolated", False
        ):
            weaknesses.append("approval signing authority is evaluator-local")
        if self.approval_ledger.durable and not getattr(
            self.approval_ledger, "integrity_protected", False
        ):
            weaknesses.append("durable approval ledger is not authenticated")
        return {
            "production_mode": self.production_mode,
            "approval_verification": self.approval_verifier is not None,
            "durable_approval_replay": self.approval_ledger.durable,
            "isolated_approval_signing": bool(
                self.approval_verifier is not None
                and getattr(
                    self.approval_verifier, "signing_authority_isolated", False
                )
            ),
            "approval_ledger_integrity": bool(
                getattr(self.approval_ledger, "integrity_protected", False)
            ),
            "weaknesses": tuple(weaknesses),
        }

    def evaluate(
        self,
        proposal: ActionProposal,
        *,
        request_risk: Risk = Risk.LOW,
        approval: HumanApproval | None = None,
        consume_approval: bool = True,
    ) -> Decision:
        """Evaluate a proposal and atomically consume any valid approval.

        ``consume_approval=False`` is an explicit preview mode. A preview
        decision must never be used as authority to execute the proposal.
        """
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
                try:
                    claimed = self.approval_ledger.claim(approval)
                    if claimed is not True:
                        approved = False
                        approval_reason = "approval nonce already consumed"
                except Exception:
                    logger.exception("approval replay ledger failed closed")
                    approved = False
                    approval_reason = "approval replay ledger unavailable"
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
        return True, ""
