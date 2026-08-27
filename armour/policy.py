"""Human-owned policy. Agents receive it; they do not modify it."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .models import Effect, Risk


@dataclass(frozen=True, slots=True)
class Policy:
    allowed_actions: frozenset[str]
    action_effects: Mapping[str, Effect] = field(default_factory=dict)
    allowed_roots: tuple[Path, ...] = field(default_factory=tuple)
    allowed_http_methods: frozenset[str] = frozenset({"GET", "HEAD"})
    human_gate_at: Risk = Risk.HIGH
    forbidden_effects: frozenset[Effect] = frozenset({Effect.IRREVERSIBLE})
    deny_private_networks: bool = True
    policy_id: str = "default"
    revision: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_roots",
            tuple(Path(root).expanduser().resolve() for root in self.allowed_roots),
        )
        effects = dict(self.action_effects)
        if any(action not in self.allowed_actions for action in effects):
            raise ValueError("action_effects may only describe allowed actions")
        missing_effects = self.allowed_actions.difference(effects)
        if missing_effects:
            missing = ", ".join(sorted(missing_effects))
            raise ValueError(
                f"every allowed action requires a policy-owned effect: {missing}"
            )
        if any(not isinstance(effect, Effect) for effect in effects.values()):
            raise TypeError("action_effects values must be Effect members")
        if not self.policy_id or self.revision < 1:
            raise ValueError("policy_id must be non-empty and revision must be positive")
        object.__setattr__(self, "action_effects", MappingProxyType(effects))

    def fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "policy_id": self.policy_id,
                "revision": self.revision,
                "allowed_actions": sorted(self.allowed_actions),
                "action_effects": {
                    key: value.value for key, value in sorted(self.action_effects.items())
                },
                "allowed_roots": sorted(str(path) for path in self.allowed_roots),
                "allowed_http_methods": sorted(self.allowed_http_methods),
                "human_gate_at": self.human_gate_at.name.lower(),
                "forbidden_effects": sorted(effect.value for effect in self.forbidden_effects),
                "deny_private_networks": self.deny_private_networks,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()
