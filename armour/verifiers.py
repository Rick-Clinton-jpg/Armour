"""Independent, deterministic checks over untrusted action proposals."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Mapping
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

from .models import ActionProposal, CheckResult, Effect, Risk
from .policy import Policy


Resolver = Callable[[str], Iterable[str]]


def system_resolver(host: str) -> Iterable[str]:
    return {item[4][0] for item in socket.getaddrinfo(host, None)}


class ActionVerifier:
    name = "action_allowlist"

    def check(self, proposal: ActionProposal, policy: Policy) -> CheckResult:
        passed = proposal.action in policy.allowed_actions
        reason = (
            f"action {proposal.action!r} is registered"
            if passed
            else f"unknown or disallowed action: {proposal.action!r}"
        )
        return CheckResult(self.name, passed, (reason,))


class SchemaVerifier:
    name = "action_schema"

    @staticmethod
    def _contains_nested(value: object) -> bool:
        if isinstance(value, Mapping):
            return True
        if isinstance(value, (list, tuple)):
            return any(
                isinstance(item, (Mapping, list, tuple))
                for item in value
            )
        return False

    def check(self, proposal: ActionProposal, policy: Policy) -> CheckResult:
        schema = policy.action_schemas.get(proposal.action)
        if schema is None:
            return CheckResult(self.name, True, ("no strict action schema configured",))
        supplied = frozenset(proposal.payload)
        unknown = supplied - schema.allowed_payload_keys
        if unknown:
            return CheckResult(
                self.name,
                False,
                (f"unknown payload keys: {', '.join(sorted(map(str, unknown)))}",),
                Risk.HIGH,
            )
        missing = schema.required_payload_keys - supplied
        if missing:
            return CheckResult(
                self.name,
                False,
                (f"missing required payload keys: {', '.join(sorted(missing))}",),
            )
        if not schema.allow_nested_payload and any(
            self._contains_nested(value) for value in proposal.payload.values()
        ):
            return CheckResult(
                self.name,
                False,
                ("nested payload values are forbidden by the action schema",),
                Risk.HIGH,
            )
        return CheckResult(self.name, True, ("strict action schema satisfied",))


class EffectVerifier:
    name = "effect_policy"

    def check(self, proposal: ActionProposal, policy: Policy) -> CheckResult:
        declared = proposal.effect
        policy_effect = policy.action_effects.get(proposal.action, declared)
        ranks = {
            Effect.READ_ONLY: 1,
            Effect.STATE_CHANGING: 2,
            Effect.DESTRUCTIVE: 3,
            Effect.IRREVERSIBLE: 4,
        }
        effective_effect = max((declared, policy_effect), key=ranks.__getitem__)
        if effective_effect in policy.forbidden_effects:
            return CheckResult(
                self.name,
                False,
                (f"effective effect {effective_effect.value!r} is forbidden",),
                Risk.CRITICAL,
            )
        inferred = {
            Effect.READ_ONLY: Risk.LOW,
            Effect.STATE_CHANGING: Risk.MEDIUM,
            Effect.DESTRUCTIVE: Risk.HIGH,
            Effect.IRREVERSIBLE: Risk.CRITICAL,
        }[effective_effect]
        reasons = [f"effective effect {effective_effect.value!r} permitted"]
        if policy_effect != declared:
            reasons.append(
                f"policy effect {policy_effect.value!r} overrides declared {declared.value!r}"
            )
        return CheckResult(
            self.name, True, tuple(reasons), inferred
        )


class FilesystemVerifier:
    name = "filesystem_scope"
    PATH_KEYS = frozenset({"path", "target", "source", "destination"})

    def _paths(
        self, proposal: ActionProposal, policy: Policy
    ) -> tuple[list[str], list[str]]:
        values: list[str] = []
        invalid: list[str] = []
        if proposal.resource and not proposal.resource.startswith(("http://", "https://")):
            values.append(proposal.resource)

        def visit(value: object) -> None:
            if isinstance(value, Mapping):
                for key, item in value.items():
                    if key in self.PATH_KEYS:
                        if isinstance(item, str):
                            values.append(item)
                        elif isinstance(item, (list, tuple)) and all(
                            isinstance(entry, str) for entry in item
                        ):
                            values.extend(item)
                        else:
                            invalid.append(str(key))
                    visit(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    visit(item)

        schema = policy.action_schemas.get(proposal.action)
        if schema is None:
            visit(proposal.payload)
        else:
            for key in schema.filesystem_path_fields:
                if key not in proposal.payload:
                    continue
                item = proposal.payload.get(key)
                if isinstance(item, str):
                    values.append(item)
                elif isinstance(item, (list, tuple)) and all(
                    isinstance(entry, str) for entry in item
                ):
                    values.extend(item)
                else:
                    invalid.append(key)
        return values, invalid

    def check(self, proposal: ActionProposal, policy: Policy) -> CheckResult:
        paths, invalid = self._paths(proposal, policy)
        if invalid:
            fields = ", ".join(sorted(set(invalid)))
            return CheckResult(
                self.name,
                False,
                (f"filesystem path fields must contain strings: {fields}",),
                Risk.HIGH,
            )
        if not paths:
            return CheckResult(self.name, True, ("no filesystem resource",))
        if not policy.allowed_roots:
            return CheckResult(self.name, False, ("filesystem access has no allowed roots",))

        reasons: list[str] = []
        for raw in paths:
            candidate = Path(raw).expanduser()
            if not candidate.is_absolute():
                return CheckResult(
                    self.name, False, (f"relative path rejected at trust boundary: {raw!r}",)
                )
            try:
                resolved = candidate.resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                return CheckResult(
                    self.name, False, (f"invalid filesystem path: {raw!r}",), Risk.HIGH
                )
            if not any(resolved == root or root in resolved.parents for root in policy.allowed_roots):
                return CheckResult(
                    self.name, False, (f"path outside allowed roots: {raw!r}",)
                )
            reasons.append(f"path confined to allowed root: {resolved}")
        return CheckResult(self.name, True, tuple(reasons))


class NetworkVerifier:
    name = "network_policy"

    def __init__(self, resolver: Resolver = system_resolver):
        self.resolver = resolver

    @staticmethod
    def _unsafe_ip(value: str) -> bool:
        ip = ipaddress.ip_address(value)
        return not ip.is_global

    def check(self, proposal: ActionProposal, policy: Policy) -> CheckResult:
        url = proposal.resource if proposal.resource and proposal.resource.startswith(("http://", "https://")) else proposal.payload.get("url")
        if not url:
            return CheckResult(self.name, True, ("no network resource",))
        if not isinstance(url, str) or len(url) > 2048:
            return CheckResult(self.name, False, ("invalid or oversized URL",))

        parsed = urlparse(url)
        raw_method = proposal.method or proposal.payload.get("method") or "GET"
        if not isinstance(raw_method, str):
            return CheckResult(
                self.name, False, ("HTTP method must be a string",), Risk.HIGH
            )
        method = raw_method.upper()
        if method not in policy.allowed_http_methods:
            return CheckResult(self.name, False, (f"HTTP method {method!r} is forbidden",), Risk.HIGH)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return CheckResult(self.name, False, ("only absolute HTTP(S) URLs are allowed",))
        if parsed.username or parsed.password:
            return CheckResult(self.name, False, ("credentials in URLs are forbidden",), Risk.HIGH)
        if not policy.deny_private_networks:
            return CheckResult(self.name, True, (f"network method {method} permitted",))

        host = parsed.hostname.lower()
        if host in {"localhost", "localhost.localdomain"}:
            return CheckResult(self.name, False, (f"private host rejected: {host}",), Risk.HIGH)
        try:
            addresses = [host] if _looks_like_ip(host) else list(self.resolver(host))
        except OSError as exc:
            return CheckResult(self.name, False, (f"DNS resolution failed: {exc}",))
        if not addresses:
            return CheckResult(self.name, False, ("DNS returned no addresses",))
        for address in addresses:
            try:
                if self._unsafe_ip(address):
                    return CheckResult(
                        self.name,
                        False,
                        (f"non-public destination rejected: {address}",),
                        Risk.HIGH,
                    )
            except ValueError:
                return CheckResult(self.name, False, (f"invalid resolved address: {address}",))
        return CheckResult(self.name, True, (f"public {method} destination verified",))


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class DangerousContentVerifier:
    name = "dangerous_content"
    SENTENCE_BREAK = re.compile(r"[.!?]\s+")
    PATTERNS = (
        re.compile(r"\brm\s+-rf?\b", re.I),
        re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", re.I),
        re.compile(r"\b(?:eval|exec)\s*\(", re.I),
        re.compile(r"\b(?:curl|wget)\b[^\n]*(?:\||;)\s*(?:sh|bash)\b", re.I),
    )

    def check(self, proposal: ActionProposal, policy: Policy) -> CheckResult:
        text = repr(dict(proposal.payload))
        variants = (text, self.SENTENCE_BREAK.sub("", text))
        for candidate in dict.fromkeys(variants):
            for pattern in self.PATTERNS:
                if pattern.search(candidate):
                    return CheckResult(
                        self.name,
                        False,
                        (f"dangerous content matched {pattern.pattern!r}",),
                        Risk.CRITICAL,
                    )
        return CheckResult(self.name, True, ("no dangerous content signature",))
