"""Append-only, hash-chained JSONL decision receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from threading import Lock
from typing import Any

from .models import ActionProposal, Decision, ExecutionOutcome


class ReceiptLog:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self._lock = Lock()

    def append(
        self,
        proposal: ActionProposal,
        decision: Decision,
        outcome: ExecutionOutcome | None = None,
    ) -> str:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            previous_hash = self._last_hash()
            record: dict[str, Any] = {
                "previous_hash": previous_hash,
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
                    "output": outcome.output,
                    "error": outcome.error,
                },
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
            record_hash = hashlib.sha256(canonical.encode()).hexdigest()
            record["record_hash"] = record_hash
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            return record_hash

    def verify(self) -> bool:
        previous = ""
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            claimed = record.pop("record_hash", "")
            if record.get("previous_hash") != previous:
                return False
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
            if hashlib.sha256(canonical.encode()).hexdigest() != claimed:
                return False
            previous = claimed
        return True

    def _last_hash(self) -> str:
        if not self.path.exists():
            return ""
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return ""
        return str(json.loads(lines[-1]).get("record_hash", ""))
