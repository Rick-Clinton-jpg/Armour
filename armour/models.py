"""Typed values crossing the Armour trust boundary."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Mapping
from uuid import uuid4

import hashlib
import hmac
import json


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


class Risk(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


class Effect(StrEnum):
    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    DESTRUCTIVE = "destructive"
    IRREVERSIBLE = "irreversible"


class Verdict(StrEnum):
    AUTHORIZED = "authorized"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class AuditStatus(StrEnum):
    """Whether execution evidence was durably recorded.

    This is deliberately separate from ``ExecutionOutcome.success``. A handler
    may complete successfully even when the completion receipt cannot be
    persisted; collapsing those states invites unsafe retries.
    """

    NOT_CONFIGURED = "not_configured"
    COMPLETED = "completed"
    START_FAILED = "start_failed"
    COMPLETION_FAILED = "completion_failed"


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """Untrusted action proposed by an agent or model."""

    action: str
    effect: Effect
    risk: Risk
    resource: str | None = None
    method: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex[:12])

    def __post_init__(self) -> None:
        if not self.action or not self.action.replace("_", "").isalnum():
            raise ValueError("action must be a non-empty identifier")
        if not isinstance(self.effect, Effect) or not isinstance(self.risk, Risk):
            raise TypeError("effect and risk must use Armour enum values")
        if not isinstance(self.payload, Mapping):
            raise TypeError("payload must be a mapping")
        payload = deepcopy(dict(self.payload))
        try:
            json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise TypeError("payload must contain only JSON-compatible values") from exc
        object.__setattr__(self, "payload", _freeze_json(payload))

    @classmethod
    def from_untrusted(cls, raw: Mapping[str, Any]) -> "ActionProposal":
        """Validate and normalize model/tool JSON at the trust boundary."""
        if not isinstance(raw, Mapping):
            raise TypeError("proposal must be a mapping")
        resource = raw.get("resource")
        method = raw.get("method")
        if resource is not None and not isinstance(resource, str):
            raise TypeError("resource must be a string or null")
        if method is not None and not isinstance(method, str):
            raise TypeError("method must be a string or null")
        return cls(
            action=str(raw.get("action", "")),
            effect=Effect(str(raw.get("effect", ""))),
            risk=Risk[str(raw.get("risk", "")).upper()],
            resource=resource,
            method=method,
            payload=raw.get("payload", {}),
        )

    def fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "id": self.id,
                "action": self.action,
                "effect": self.effect.value,
                "risk": self.risk.name.lower(),
                "resource": self.resource,
                "method": self.method,
                "payload": self.payload_data(),
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def payload_data(self) -> dict[str, Any]:
        """Return an ordinary deep copy for serialization or trusted handlers."""
        return _thaw_json(self.payload)


@dataclass(frozen=True, slots=True)
class HumanApproval:
    proposal_id: str
    proposal_fingerprint: str
    policy_fingerprint: str
    approved_by: str
    expires_at: str
    nonce: str = field(default_factory=lambda: uuid4().hex)
    reason: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    key_id: str = ""
    signature: str = ""

    def canonical_payload(self) -> bytes:
        """Return the complete approval envelope in a signable canonical form."""
        canonical = json.dumps(
            {
                "proposal_id": self.proposal_id,
                "proposal_fingerprint": self.proposal_fingerprint,
                "policy_fingerprint": self.policy_fingerprint,
                "approved_by": self.approved_by,
                "expires_at": self.expires_at,
                "nonce": self.nonce,
                "reason": self.reason,
                "timestamp": self.timestamp,
                "key_id": self.key_id,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return canonical.encode()

    @classmethod
    def issue(
        cls,
        proposal: ActionProposal,
        *,
        policy_fingerprint: str,
        approved_by: str,
        reason: str = "",
        ttl_seconds: int = 300,
        signing_key: bytes | None = None,
        key_id: str = "",
    ) -> "HumanApproval":
        if ttl_seconds <= 0:
            raise ValueError("approval TTL must be positive")
        if signing_key is not None and (not signing_key or not key_id):
            raise ValueError("signed approvals require a non-empty key and key_id")
        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        approval = cls(
            proposal_id=proposal.id,
            proposal_fingerprint=proposal.fingerprint(),
            policy_fingerprint=policy_fingerprint,
            approved_by=approved_by,
            expires_at=expires.isoformat(),
            reason=reason,
            key_id=key_id,
        )
        if signing_key is None:
            return approval
        signature = hmac.new(
            signing_key, approval.canonical_payload(), hashlib.sha256
        ).hexdigest()
        return replace(approval, signature=signature)


@dataclass(frozen=True, slots=True)
class CheckResult:
    verifier: str
    passed: bool
    reasons: tuple[str, ...]
    inferred_risk: Risk = Risk.LOW


@dataclass(frozen=True, slots=True)
class Decision:
    proposal_id: str
    verdict: Verdict
    effective_risk: Risk
    checks: tuple[CheckResult, ...]
    reasons: tuple[str, ...]
    policy_fingerprint: str = ""
    human_required: bool = False
    human_approved: bool = False
    approved_by: str | None = None
    approval_nonce: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        data["effective_risk"] = self.effective_risk.name.lower()
        for check in data["checks"]:
            check["inferred_risk"] = Risk(check["inferred_risk"]).name.lower()
        return data


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """The handler result and audit result for one execution attempt.

    ``success`` reports whether the registered handler returned normally. It
    never changes merely because completion auditing failed. Callers should
    inspect ``audit_status`` separately and must not retry a successful handler
    solely because its completion receipt is incomplete.
    """

    proposal_id: str
    success: bool
    output: Any = None
    error: str | None = None
    execution_id: str | None = None
    binding_id: str | None = None
    audit_status: AuditStatus = AuditStatus.NOT_CONFIGURED
    audit_error: str | None = None
