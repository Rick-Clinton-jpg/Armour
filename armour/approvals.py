"""Approval provenance verification owned by the trusted host."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace
from types import MappingProxyType
from typing import Mapping, Protocol

from .models import ActionProposal, HumanApproval


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
        if (
            secret is None
            or not isinstance(approval.signature, str)
            or len(approval.signature) != 64
        ):
            return False
        expected = hmac.new(
            secret, approval.canonical_payload(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(approval.signature, expected)


def _load_ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 support requires the optional 'crypto' dependency"
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


class Ed25519ApprovalVerifier:
    """Verify approvals using public keys held by the Armour evaluator."""

    def __init__(self, trusted_public_keys: Mapping[str, bytes]):
        _, _, _, public_key_type = _load_ed25519()
        keys = dict(trusted_public_keys)
        if not keys:
            raise ValueError("trusted approval public keys cannot be empty")
        parsed = {}
        for key_id, public_bytes in keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise ValueError("approval key ids must be non-empty strings")
            if not isinstance(public_bytes, bytes) or len(public_bytes) != 32:
                raise ValueError("Ed25519 public keys must be 32 raw bytes")
            try:
                parsed[key_id] = public_key_type.from_public_bytes(public_bytes)
            except ValueError as exc:
                raise ValueError("Ed25519 public key is malformed") from exc
        self._trusted_public_keys = MappingProxyType(parsed)

    def verify(self, approval: HumanApproval) -> bool:
        invalid_signature, _, _, _ = _load_ed25519()
        public_key = self._trusted_public_keys.get(approval.key_id)
        if (
            public_key is None
            or not isinstance(approval.signature, str)
            or len(approval.signature) != 128
        ):
            return False
        try:
            signature = bytes.fromhex(approval.signature)
        except ValueError:
            return False
        if len(signature) != 64:
            return False
        try:
            public_key.verify(signature, approval.canonical_payload())
        except (invalid_signature, ValueError, TypeError):
            return False
        return True


class Ed25519ApprovalSigner:
    """Issuer-side helper; do not construct this inside the Armour evaluator."""

    def __init__(self, key_id: str, private_key: bytes):
        _, _, private_key_type, _ = _load_ed25519()
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("approval key id must be a non-empty string")
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private keys must be 32 raw bytes")
        try:
            self._private_key = private_key_type.from_private_bytes(private_key)
        except ValueError as exc:
            raise ValueError("Ed25519 private key is malformed") from exc
        self.key_id = key_id

    def public_key_bytes(self) -> bytes:
        """Export the raw public key safe to install in an evaluator."""
        _, serialization, _, _ = _load_ed25519()
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, approval: HumanApproval) -> HumanApproval:
        """Sign a complete approval envelope for this issuer key id."""
        if approval.key_id != self.key_id:
            raise ValueError("approval key id does not match signer")
        signature = self._private_key.sign(approval.canonical_payload()).hex()
        return replace(approval, signature=signature)

    def issue(
        self,
        proposal: ActionProposal,
        *,
        policy_fingerprint: str,
        approved_by: str,
        reason: str = "",
        ttl_seconds: int = 300,
    ) -> HumanApproval:
        """Create and sign a proposal-bound human approval."""
        approval = HumanApproval.issue(
            proposal,
            policy_fingerprint=policy_fingerprint,
            approved_by=approved_by,
            reason=reason,
            ttl_seconds=ttl_seconds,
            key_id=self.key_id,
        )
        return self.sign(approval)
