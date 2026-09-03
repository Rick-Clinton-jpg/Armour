"""Append-only, hash-chained JSONL decision receipts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from typing import Any

from .models import ActionProposal, Decision, ExecutionOutcome


@dataclass(frozen=True, slots=True)
class ReceiptVerification:
    valid: bool
    total_records: int
    failed_record: int | None = None
    reason: str | None = None
    last_valid_hash: str = ""

    def __bool__(self) -> bool:
        return self.valid


class ReceiptIntegrityError(ValueError):
    """Raised when an append would extend a damaged receipt chain."""


def _sanitize(value: Any, *, depth: int = 0, seen: set[int] | None = None) -> Any:
    """Convert arbitrary handler output into a bounded JSON-compatible value."""
    if seen is None:
        seen = set()
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:4096]
    if depth >= 8:
        return "<max-depth>"
    identity = id(value)
    if identity in seen:
        return "<cycle>"
    if isinstance(value, dict):
        seen.add(identity)
        result = {
            str(key)[:256]: _sanitize(item, depth=depth + 1, seen=seen)
            for key, item in list(value.items())[:100]
        }
        seen.remove(identity)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        seen.add(identity)
        result = [
            _sanitize(item, depth=depth + 1, seen=seen)
            for item in list(value)[:100]
        ]
        seen.remove(identity)
        return result
    try:
        rendered = repr(value)
    except Exception:
        rendered = f"<{type(value).__name__}>"
    return rendered[:4096]


class ReceiptLog:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self._lock = Lock()

    def append(
        self,
        proposal: ActionProposal,
        decision: Decision,
        outcome: ExecutionOutcome | None = None,
        *,
        phase: str = "completed",
        execution_id: str | None = None,
    ) -> str:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            verification = self.verify()
            if not verification.valid:
                raise ReceiptIntegrityError(
                    f"refusing to extend corrupt receipt chain at record "
                    f"{verification.failed_record}: {verification.reason}"
                )
            previous_hash = verification.last_valid_hash
            record: dict[str, Any] = {
                "previous_hash": previous_hash,
                "phase": phase,
                "execution_id": execution_id,
                "proposal": {
                    "id": proposal.id,
                    "action": proposal.action,
                    "effect": proposal.effect.value,
                    "risk": proposal.risk.name.lower(),
                    "resource": proposal.resource,
                    "method": proposal.method,
                    "payload": proposal.payload_data(),
                },
                "decision": decision.to_dict(),
                "outcome": None
                if outcome is None
                else {
                    "success": outcome.success,
                    "output": _sanitize(outcome.output),
                    "error": outcome.error,
                    "execution_id": outcome.execution_id,
                    "binding_id": outcome.binding_id,
                    "audit_status": outcome.audit_status.value,
                    "audit_error": outcome.audit_error,
                },
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
            record_hash = hashlib.sha256(canonical.encode()).hexdigest()
            record["record_hash"] = record_hash
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record_hash

    def verify(self) -> ReceiptVerification:
        previous = ""
        if not self.path.exists():
            return ReceiptVerification(True, 0)
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            return ReceiptVerification(False, 0, 1, type(exc).__name__, previous)
        for index, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, TypeError) as exc:
                return ReceiptVerification(
                    False, index - 1, index, f"invalid JSON: {exc}", previous
                )
            if not isinstance(record, dict):
                return ReceiptVerification(
                    False, index - 1, index, "record is not an object", previous
                )
            claimed = record.pop("record_hash", "")
            if record.get("previous_hash") != previous:
                return ReceiptVerification(
                    False, index - 1, index, "hash chain is broken", previous
                )
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
            if hashlib.sha256(canonical.encode()).hexdigest() != claimed:
                return ReceiptVerification(
                    False, index - 1, index, "record hash does not match", previous
                )
            previous = claimed
        return ReceiptVerification(True, len(lines), last_valid_hash=previous)

    def _last_hash(self) -> str:
        verification = self.verify()
        if not verification.valid:
            raise ReceiptIntegrityError(
                f"receipt chain is corrupt at record {verification.failed_record}"
            )
        return verification.last_valid_hash
