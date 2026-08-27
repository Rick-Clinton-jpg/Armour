"""Approval provenance verification owned by the trusted host."""

from __future__ import annotations

import hashlib
import hmac
from types import MappingProxyType
from typing import Mapping, Protocol

from .models import HumanApproval


class ApprovalVerifier(Protocol):
    def verify(self, approval: HumanApproval) -> bool:
        """Return whether the complete approval envelope has trusted provenance."""


class HMACApprovalVerifier:
    """Dependency-free reference verifier for trusted shared-secret deployments.

    Public-key verification should be supplied through ``ApprovalVerifier`` when
    the evaluator must not possess approval-signing authority.
    """

    def __init__(self, trusted_keys: Mapping[str, bytes]):
        keys = dict(trusted_keys)
        if not keys or any(
            not isinstance(key_id, str)
            or not key_id
            or not isinstance(secret, bytes)
            or not secret
            for key_id, secret in keys.items()
        ):
            raise ValueError("trusted approval keys must map key ids to non-empty bytes")
        self._trusted_keys = MappingProxyType(keys)

    def verify(self, approval: HumanApproval) -> bool:
        secret = self._trusted_keys.get(approval.key_id)
        if secret is None or not approval.signature:
            return False
        expected = hmac.new(
            secret, approval.canonical_payload(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(approval.signature, expected)
