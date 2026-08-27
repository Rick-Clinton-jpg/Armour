"""Human-owned policy. Agents receive it; they do not modify it."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .models import Effect, Risk
from .schemas import ActionSchema


@dataclass(frozen=True, slots=True)
class Policy:
    allowed_actions: frozenset[str]
    action_effects: Mapping[str, Effect] = field(default_factory=dict)
    action_schemas: Mapping[str, ActionSchema] = field(default_factory=dict)
    allowed_roots: tuple[Path, ...] = field(default_factory=tuple)
    allowed_http_methods: frozenset[str] = frozenset({"GET", "HEAD"})
    human_gate_at: Risk = Risk.HIGH
    forbidden_effects: frozenset[Effect] = frozenset({Effect.IRREVERSIBLE})
    deny_private_networks: bool = True
    policy_id: str = "default"
    revision: int = 1
    _construction_fingerprint: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.allowed_actions, str):
            raise TypeError("allowed_actions must be a collection of strings")
        if isinstance(self.allowed_http_methods, str):
            raise TypeError("allowed_http_methods must be a collection of strings")
        if isinstance(self.forbidden_effects, Effect):
            raise TypeError("forbidden_effects must be a collection of Effect members")
        actions = frozenset(self.allowed_actions)
        if any(not isinstance(action, str) or not action for action in actions):
            raise TypeError("allowed_actions must contain non-empty strings")
        raw_methods = tuple(self.allowed_http_methods)
        if any(not isinstance(method, str) or not method for method in raw_methods):
            raise TypeError("allowed_http_methods must contain non-empty strings")
        methods = frozenset(method.upper() for method in raw_methods)
        forbidden = frozenset(self.forbidden_effects)
        if any(not isinstance(effect, Effect) for effect in forbidden):
            raise TypeError("forbidden_effects must contain Effect members")
        if not isinstance(self.human_gate_at, Risk):
            raise TypeError("human_gate_at must be a Risk member")
        if not isinstance(self.deny_private_networks, bool):
            raise TypeError("deny_private_networks must be a bool")
        object.__setattr__(self, "allowed_actions", actions)
        object.__setattr__(self, "allowed_http_methods", methods)
        object.__setattr__(self, "forbidden_effects", forbidden)
        object.__setattr__(
            self,
            "allowed_roots",
            tuple(Path(root).expanduser().resolve() for root in self.allowed_roots),
        )
        effects = dict(self.action_effects)
        schemas = dict(self.action_schemas)
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
        if any(action not in actions for action in schemas):
            raise ValueError("action_schemas may only describe allowed actions")
        if any(not isinstance(schema, ActionSchema) for schema in schemas.values()):
            raise TypeError("action_schemas values must be ActionSchema members")
        if not isinstance(self.policy_id, str) or not self.policy_id:
            raise TypeError("policy_id must be a non-empty string")
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("policy_id must be non-empty and revision must be positive")
        object.__setattr__(self, "action_effects", MappingProxyType(effects))
        object.__setattr__(self, "action_schemas", MappingProxyType(schemas))
        object.__setattr__(self, "_construction_fingerprint", self._compute_fingerprint())

    def _compute_fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "policy_id": self.policy_id,
                "revision": self.revision,
                "allowed_actions": sorted(self.allowed_actions),
                "action_effects": {
                    key: value.value for key, value in sorted(self.action_effects.items())
                },
                "action_schemas": {
                    key: value.to_dict()
                    for key, value in sorted(self.action_schemas.items())
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

    def fingerprint(self) -> str:
        """Return the fingerprint only while the policy retains its initial state."""
        current = self._compute_fingerprint()
        if current != self._construction_fingerprint:
            raise RuntimeError("policy integrity check failed: state drifted after construction")
        return current
