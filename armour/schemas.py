"""Host-owned payload contracts shared by verifiers and handlers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActionSchema:
    """A strict top-level payload shape for one registered action.

    The executor passes the same immutable ``ActionProposal`` object to the
    verifier chain and handler, so the handler observes the payload instance
    whose key contract was checked.
    """

    allowed_payload_keys: frozenset[str]
    required_payload_keys: frozenset[str] = frozenset()
    filesystem_path_fields: frozenset[str] = frozenset()
    allow_nested_payload: bool = False

    def __post_init__(self) -> None:
        allowed = frozenset(self.allowed_payload_keys)
        required = frozenset(self.required_payload_keys)
        paths = frozenset(self.filesystem_path_fields)
        if any(not isinstance(key, str) or not key for key in allowed | required | paths):
            raise TypeError("action schema keys must be non-empty strings")
        if not required <= allowed:
            raise ValueError("required payload keys must be allowed")
        if not paths <= allowed:
            raise ValueError("filesystem path fields must be allowed payload keys")
        if not isinstance(self.allow_nested_payload, bool):
            raise TypeError("allow_nested_payload must be a bool")
        object.__setattr__(self, "allowed_payload_keys", allowed)
        object.__setattr__(self, "required_payload_keys", required)
        object.__setattr__(self, "filesystem_path_fields", paths)

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed_payload_keys": sorted(self.allowed_payload_keys),
            "required_payload_keys": sorted(self.required_payload_keys),
            "filesystem_path_fields": sorted(self.filesystem_path_fields),
            "allow_nested_payload": self.allow_nested_payload,
        }
