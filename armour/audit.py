"""Append-only, hash-chained JSONL decision receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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


@dataclass(frozen=True, slots=True)
class ReceiptAnchorVerification:
    """Relationship between a primary receipt chain and its checkpoint file."""

    valid: bool
    anchoring_enabled: bool
    primary_records: int
    checkpoint_records: int
    failed_checkpoint: int | None = None
    reason: str | None = None
    last_checkpoint_hash: str = ""

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
    def __init__(
        self,
        path: str | Path,
        *,
        anchor_path: str | Path | None = None,
    ):
        self.path = Path(path).expanduser().resolve()
        self.anchor_path = (
            None if anchor_path is None else Path(anchor_path).expanduser().resolve()
        )
        if self.anchor_path == self.path:
            raise ValueError("receipt checkpoint must be separate from the primary log")
        self._lock = Lock()

    @property
    def anchoring_enabled(self) -> bool:
        return self.anchor_path is not None

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
            if self.anchoring_enabled:
                anchor_verification = self._verify_anchor_unlocked()
                if not anchor_verification.valid:
                    raise ReceiptIntegrityError(
                        "refusing to extend receipt log with invalid checkpoint: "
                        f"{anchor_verification.reason}"
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
            if self.anchor_path is not None:
                self._append_checkpoint(
                    receipt_id=verification.total_records + 1,
                    receipt_hash=record_hash,
                )
            return record_hash

    def _append_checkpoint(self, *, receipt_id: int, receipt_hash: str) -> None:
        if self.anchor_path is None:
            return
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint = {
            "receipt_hash": receipt_hash,
            "receipt_id": receipt_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self.anchor_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(checkpoint, sort_keys=True, separators=(",", ":")) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())

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

    def verify_anchor(self) -> ReceiptAnchorVerification:
        """Verify that the checkpoint file exactly covers the primary chain."""

        with self._lock:
            return self._verify_anchor_unlocked()

    def _verify_anchor_unlocked(self) -> ReceiptAnchorVerification:
        if self.anchor_path is None:
            primary = self.verify()
            return ReceiptAnchorVerification(
                primary.valid,
                False,
                primary.total_records,
                0,
                reason=primary.reason,
            )

        primary = self.verify()
        if not primary.valid:
            return ReceiptAnchorVerification(
                False,
                True,
                primary.total_records,
                0,
                reason=f"primary receipt chain is invalid: {primary.reason}",
            )

        try:
            primary_hashes = []
            if self.path.exists():
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    record = json.loads(line)
                    primary_hashes.append(record["record_hash"])
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            return ReceiptAnchorVerification(
                False,
                True,
                primary.total_records,
                0,
                reason=f"primary receipt chain could not be compared: {type(exc).__name__}",
            )

        if not self.anchor_path.exists():
            if not primary_hashes:
                return ReceiptAnchorVerification(True, True, 0, 0)
            return ReceiptAnchorVerification(
                False,
                True,
                len(primary_hashes),
                0,
                failed_checkpoint=1,
                reason="checkpoint file is missing",
            )
        try:
            checkpoint_lines = self.anchor_path.read_text(
                encoding="utf-8"
            ).splitlines()
        except (OSError, UnicodeError) as exc:
            return ReceiptAnchorVerification(
                False,
                True,
                len(primary_hashes),
                0,
                failed_checkpoint=1,
                reason=f"checkpoint file is unreadable: {type(exc).__name__}",
            )

        checkpoints: list[str] = []
        for index, line in enumerate(checkpoint_lines, start=1):
            try:
                checkpoint = json.loads(line)
            except (json.JSONDecodeError, TypeError) as exc:
                return ReceiptAnchorVerification(
                    False,
                    True,
                    len(primary_hashes),
                    index - 1,
                    failed_checkpoint=index,
                    reason=f"invalid checkpoint JSON: {exc}",
                )
            if not isinstance(checkpoint, dict):
                return ReceiptAnchorVerification(
                    False,
                    True,
                    len(primary_hashes),
                    index - 1,
                    failed_checkpoint=index,
                    reason="checkpoint is not an object",
                )
            receipt_id = checkpoint.get("receipt_id")
            receipt_hash = checkpoint.get("receipt_hash")
            timestamp = checkpoint.get("timestamp")
            if (
                receipt_id != index
                or not isinstance(receipt_hash, str)
                or len(receipt_hash) != 64
                or not isinstance(timestamp, str)
                or not timestamp
            ):
                return ReceiptAnchorVerification(
                    False,
                    True,
                    len(primary_hashes),
                    index - 1,
                    failed_checkpoint=index,
                    reason="checkpoint fields are invalid or out of sequence",
                    last_checkpoint_hash=checkpoints[-1] if checkpoints else "",
                )
            try:
                bytes.fromhex(receipt_hash)
                parsed_timestamp = datetime.fromisoformat(timestamp)
                if parsed_timestamp.tzinfo is None:
                    raise ValueError("checkpoint timestamp lacks timezone")
            except ValueError as exc:
                return ReceiptAnchorVerification(
                    False,
                    True,
                    len(primary_hashes),
                    index - 1,
                    failed_checkpoint=index,
                    reason=f"checkpoint fields are malformed: {exc}",
                    last_checkpoint_hash=checkpoints[-1] if checkpoints else "",
                )
            checkpoints.append(receipt_hash)

        if len(primary_hashes) != len(checkpoints):
            relation = (
                "primary receipt file was deleted or truncated"
                if len(primary_hashes) < len(checkpoints)
                else "checkpoint file does not cover the primary receipt chain"
            )
            return ReceiptAnchorVerification(
                False,
                True,
                len(primary_hashes),
                len(checkpoints),
                failed_checkpoint=min(len(primary_hashes), len(checkpoints)) + 1,
                reason=relation,
                last_checkpoint_hash=checkpoints[-1] if checkpoints else "",
            )
        for index, (primary_hash, checkpoint_hash) in enumerate(
            zip(primary_hashes, checkpoints), start=1
        ):
            if primary_hash != checkpoint_hash:
                return ReceiptAnchorVerification(
                    False,
                    True,
                    len(primary_hashes),
                    len(checkpoints),
                    failed_checkpoint=index,
                    reason="checkpoint does not match the primary receipt hash",
                    last_checkpoint_hash=checkpoints[index - 2] if index > 1 else "",
                )
        return ReceiptAnchorVerification(
            True,
            True,
            len(primary_hashes),
            len(checkpoints),
            last_checkpoint_hash=checkpoints[-1] if checkpoints else "",
        )

    def _last_hash(self) -> str:
        verification = self.verify()
        if not verification.valid:
            raise ReceiptIntegrityError(
                f"receipt chain is corrupt at record {verification.failed_record}"
            )
        return verification.last_valid_hash
