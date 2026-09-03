"""Execution-bound capabilities prepared from host-owned dependency policy."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import math
from threading import Lock
from typing import Any, Protocol, TYPE_CHECKING
from uuid import uuid4

from .models import ActionProposal

if TYPE_CHECKING:
    from .policy import Policy


class BindingError(RuntimeError):
    """Base class for fail-closed execution-binding failures."""


class BindingMismatch(BindingError):
    """The binding was presented outside its proposal/policy/execution scope."""


class BindingExpired(BindingError):
    """The binding or one of its capabilities exceeded its policy deadline."""


class BindingConsumed(BindingError):
    """The single-use binding has already been consumed."""


@dataclass(frozen=True, slots=True)
class DependencyPolicy:
    """Host-owned requirements for one execution dependency."""

    kind: str
    max_age_ms: float

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise TypeError("dependency kind must be a non-empty string")
        if (
            not isinstance(self.max_age_ms, (int, float))
            or isinstance(self.max_age_ms, bool)
            or not math.isfinite(self.max_age_ms)
            or self.max_age_ms <= 0
        ):
            raise ValueError("dependency max_age_ms must be finite and positive")

    def to_dict(self) -> dict[str, str | float]:
        return {"kind": self.kind, "max_age_ms": self.max_age_ms}


@dataclass(frozen=True, slots=True)
class BindingRequest:
    proposal: ActionProposal
    policy: Policy
    execution_id: str
    dependency_name: str
    dependency_policy: DependencyPolicy


class BoundCapability(Protocol):
    deadline_ns: int

    def assert_usable(self) -> None: ...

    def close(self) -> None: ...


class DependencyBinder(Protocol):
    kind: str

    def prepare(
        self, request: BindingRequest, *, monotonic_ns: Callable[[], int]
    ) -> BoundCapability: ...


class ExecutionContext:
    """The only capability collection supplied to a bound handler."""

    def __init__(self, capabilities: Mapping[str, BoundCapability]):
        self._capabilities = dict(capabilities)
        self._closed = False
        self._lock = Lock()

    def capability(self, name: str) -> BoundCapability:
        with self._lock:
            if self._closed:
                raise BindingConsumed("execution context is closed")
            try:
                capability = self._capabilities[name]
            except KeyError as exc:
                raise BindingMismatch(f"no bound capability named {name!r}") from exc
        capability.assert_usable()
        return capability

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            capabilities = tuple(self._capabilities.values())
        for capability in capabilities:
            capability.close()

    def __enter__(self) -> ExecutionContext:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


class ExecutionBinding:
    """A single-use set of live capabilities bound to one authorized execution."""

    def __init__(
        self,
        *,
        proposal_fingerprint: str,
        policy_fingerprint: str,
        execution_id: str,
        capabilities: Mapping[str, BoundCapability],
        monotonic_ns: Callable[[], int],
    ):
        self.id = uuid4().hex
        self._proposal_fingerprint = proposal_fingerprint
        self._policy_fingerprint = policy_fingerprint
        self._execution_id = execution_id
        self._capabilities = dict(capabilities)
        self._deadline_ns = min(cap.deadline_ns for cap in capabilities.values())
        self._monotonic_ns = monotonic_ns
        self._consumed = False
        self._closed = False
        self._lock = Lock()

    def consume(
        self,
        *,
        proposal: ActionProposal,
        policy_fingerprint: str,
        execution_id: str,
    ) -> ExecutionContext:
        with self._lock:
            if self._closed or self._consumed:
                raise BindingConsumed("execution binding is no longer available")
            if (
                proposal.fingerprint() != self._proposal_fingerprint
                or policy_fingerprint != self._policy_fingerprint
                or execution_id != self._execution_id
            ):
                raise BindingMismatch("execution binding scope does not match")
            if self._monotonic_ns() >= self._deadline_ns:
                raise BindingExpired("execution binding expired before use")
            for capability in self._capabilities.values():
                capability.assert_usable()
            self._consumed = True
            return ExecutionContext(self._capabilities)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            capabilities = tuple(self._capabilities.values())
        for capability in capabilities:
            capability.close()


def prepare_execution_binding(
    proposal: ActionProposal,
    policy: Policy,
    *,
    execution_id: str,
    binders: Mapping[str, DependencyBinder],
    monotonic_ns: Callable[[], int],
) -> ExecutionBinding:
    """Prepare every policy-required dependency or fail closed and clean up."""

    dependencies = policy.action_dependencies.get(proposal.action, {})
    if not dependencies:
        raise BindingMismatch("action has no execution-binding policy")
    if set(binders) != set(dependencies):
        raise BindingMismatch("registered binder set does not match dependency policy")

    capabilities: dict[str, BoundCapability] = {}
    try:
        for name, dependency_policy in dependencies.items():
            binder = binders[name]
            if binder.kind != dependency_policy.kind:
                raise BindingMismatch(
                    f"binder kind for {name!r} does not match dependency policy"
                )
            request = BindingRequest(
                proposal=proposal,
                policy=policy,
                execution_id=execution_id,
                dependency_name=name,
                dependency_policy=dependency_policy,
            )
            capabilities[name] = binder.prepare(request, monotonic_ns=monotonic_ns)
        return ExecutionBinding(
            proposal_fingerprint=proposal.fingerprint(),
            policy_fingerprint=policy.fingerprint(),
            execution_id=execution_id,
            capabilities=capabilities,
            monotonic_ns=monotonic_ns,
        )
    except Exception:
        for capability in capabilities.values():
            capability.close()
        raise
