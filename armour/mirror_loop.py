"""Bounded, inert deception sessions for rejected or escalated proposals.

The mirror loop is deliberately not a shell, interpreter, network client, or
operating-system sandbox. Attempts enter as exact built-in strings and leave in
a typed, control-escaped wrapper; this module never executes them. Real
containment remains the host's job.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
from threading import Lock
import time

from .limits import bounded_positive_finite, bounded_positive_int
from .models import ActionProposal, Decision, Verdict


MAX_MIRROR_STEPS = 64
MAX_MIRROR_DURATION_MS = 10_000
MAX_MIRROR_ATTEMPT_BYTES = 65_536
MAX_MIRROR_TOTAL_BYTES = 262_144
MAX_MIRROR_REPEATS = 8


class MirrorLoopError(RuntimeError):
    """Base class for fail-closed mirror-loop failures."""


class MirrorLoopMismatch(MirrorLoopError):
    """The session was used outside its proposal/policy/execution scope."""


class MirrorLoopExpired(MirrorLoopError):
    """The session exceeded its fixed monotonic deadline."""


class MirrorLoopTerminated(MirrorLoopError):
    """The session is closed or one of its budgets has been exhausted."""


@dataclass(frozen=True, slots=True)
class MirrorLoopPolicy:
    """Host-owned, immutable ceilings for one deception session."""

    max_steps: int = 8
    max_duration_ms: float = 1_000
    max_attempt_bytes: int = 16_384
    max_total_bytes: int = 65_536
    repeat_limit: int = 3

    def __post_init__(self) -> None:
        bounded_positive_int(
            self.max_steps, name="max_steps", hard_max=MAX_MIRROR_STEPS
        )
        bounded_positive_finite(
            self.max_duration_ms,
            name="max_duration_ms",
            hard_max=MAX_MIRROR_DURATION_MS,
        )
        bounded_positive_int(
            self.max_attempt_bytes,
            name="max_attempt_bytes",
            hard_max=MAX_MIRROR_ATTEMPT_BYTES,
        )
        bounded_positive_int(
            self.max_total_bytes,
            name="max_total_bytes",
            hard_max=MAX_MIRROR_TOTAL_BYTES,
        )
        bounded_positive_int(
            self.repeat_limit,
            name="repeat_limit",
            hard_max=MAX_MIRROR_REPEATS,
        )
        if self.max_attempt_bytes > self.max_total_bytes:
            raise ValueError("max_attempt_bytes cannot exceed max_total_bytes")


@dataclass(frozen=True, slots=True)
class ControlEscapedReflection:
    """Typed untrusted text with active Unicode controls made visible.

    This only neutralizes control characters. The value remains
    attacker-controlled and needs sink-specific escaping for HTML, structured
    logs, or model input. It must never be decoded into a command or passed to a
    shell, interpreter, or terminal-command API.
    """

    display_text: str

    def __post_init__(self) -> None:
        if type(self.display_text) is not str or not all(
            character.isprintable() for character in self.display_text
        ):
            raise ValueError("control-escaped reflection must contain printable text")


@dataclass(frozen=True, slots=True)
class MirrorObservation:
    """One inert reflection returned by the chamber."""

    sequence: int
    state: str
    reflection: ControlEscapedReflection
    attempt_fingerprint: str
    terminated: bool
    termination_reason: str | None = None


@dataclass(frozen=True, slots=True)
class MirrorEvidence:
    """Data-only evidence suitable for later trusted review."""

    proposal_fingerprint: str
    policy_fingerprint: str
    execution_id: str
    attempt_fingerprints: tuple[str, ...]
    states: tuple[str, ...]
    total_bytes: int
    terminated: bool
    termination_reason: str | None


class MirrorLoop:
    """A proposal-bound, resource-bounded mirror over inert text.

    The fixed state path intentionally returns to its starting point.  The path
    is theatrical; the actual security properties are the absence of execution
    capabilities, strict scope checks, and unconditional host-owned budgets.
    """

    _STATES = ("terminal", "filesystem", "network", "mirror", "network", "filesystem")

    def __init__(
        self,
        *,
        proposal_fingerprint: str,
        policy_fingerprint: str,
        execution_id: str,
        policy: MirrorLoopPolicy,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ):
        if not proposal_fingerprint or not policy_fingerprint or not execution_id:
            raise ValueError("mirror-loop scope values must be non-empty")
        self._proposal_fingerprint = proposal_fingerprint
        self._policy_fingerprint = policy_fingerprint
        self._execution_id = execution_id
        self._policy = policy
        self._monotonic_ns = monotonic_ns
        self._deadline_ns = monotonic_ns() + int(policy.max_duration_ms * 1_000_000)
        self._attempts: list[str] = []
        self._states: list[str] = []
        self._counts: Counter[str] = Counter()
        self._total_bytes = 0
        self._terminated = False
        self._termination_reason: str | None = None
        self._lock = Lock()

    def submit(
        self,
        attempt: str,
        *,
        proposal: ActionProposal,
        policy_fingerprint: str,
        execution_id: str,
    ) -> MirrorObservation:
        """Reflect one attempt as inert text without evaluating or executing it."""

        with self._lock:
            self._assert_open()
            # Exact type is intentional: a str subclass can override encode()
            # and run caller-controlled Python during boundary validation.
            if type(attempt) is not str:
                self._terminate("invalid_attempt")
                raise MirrorLoopTerminated("mirror-loop attempts must be strings")
            # Avoid allocating an encoded copy when the character count alone
            # proves the UTF-8 byte ceiling cannot be met.
            if len(attempt) > self._policy.max_attempt_bytes:
                self._terminate("attempt_budget_exceeded")
                raise MirrorLoopTerminated("attempt exceeds mirror-loop byte budget")
            try:
                encoded = attempt.encode("utf-8")
            except UnicodeEncodeError as exc:
                self._terminate("invalid_attempt")
                raise MirrorLoopTerminated(
                    "mirror-loop attempt is not valid UTF-8 text"
                ) from exc
            if (
                proposal.fingerprint() != self._proposal_fingerprint
                or policy_fingerprint != self._policy_fingerprint
                or execution_id != self._execution_id
            ):
                self._terminate("scope_mismatch")
                raise MirrorLoopMismatch("mirror-loop scope does not match")
            if self._monotonic_ns() >= self._deadline_ns:
                self._terminate("expired")
                raise MirrorLoopExpired("mirror-loop deadline exceeded")
            if len(encoded) > self._policy.max_attempt_bytes:
                self._terminate("attempt_budget_exceeded")
                raise MirrorLoopTerminated("attempt exceeds mirror-loop byte budget")
            if self._total_bytes + len(encoded) > self._policy.max_total_bytes:
                self._terminate("total_budget_exceeded")
                raise MirrorLoopTerminated("mirror-loop total byte budget exhausted")

            fingerprint = hashlib.sha256(encoded).hexdigest()
            sequence = len(self._attempts) + 1
            state = self._STATES[(sequence - 1) % len(self._STATES)]
            self._attempts.append(fingerprint)
            self._states.append(state)
            self._counts[fingerprint] += 1
            self._total_bytes += len(encoded)

            reason: str | None = None
            if self._counts[fingerprint] >= self._policy.repeat_limit:
                reason = "repeat_limit_reached"
            elif sequence >= self._policy.max_steps:
                reason = "step_budget_exhausted"
            if reason is not None:
                self._terminate(reason)

            return MirrorObservation(
                sequence=sequence,
                state=state,
                reflection=ControlEscapedReflection(_escape_controls(attempt)),
                attempt_fingerprint=fingerprint,
                terminated=self._terminated,
                termination_reason=self._termination_reason,
            )

    def close(self) -> None:
        with self._lock:
            if not self._terminated:
                self._terminate("closed_by_host")

    def evidence(self) -> MirrorEvidence:
        with self._lock:
            return MirrorEvidence(
                proposal_fingerprint=self._proposal_fingerprint,
                policy_fingerprint=self._policy_fingerprint,
                execution_id=self._execution_id,
                attempt_fingerprints=tuple(self._attempts),
                states=tuple(self._states),
                total_bytes=self._total_bytes,
                terminated=self._terminated,
                termination_reason=self._termination_reason,
            )

    def _assert_open(self) -> None:
        if self._terminated:
            raise MirrorLoopTerminated(
                f"mirror loop terminated: {self._termination_reason}"
            )

    def _terminate(self, reason: str) -> None:
        self._terminated = True
        self._termination_reason = reason


def _escape_controls(value: str) -> str:
    """Render controls as visible tokens without providing a decode operation."""

    return "".join(
        character if character.isprintable() else f"<U+{ord(character):04X}>"
        for character in value
    )


def prepare_mirror_loop(
    proposal: ActionProposal,
    decision: Decision,
    *,
    policy_fingerprint: str,
    execution_id: str,
    mirror_policy: MirrorLoopPolicy,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> MirrorLoop:
    """Create a chamber only for the exact denied or escalated decision."""

    if decision.verdict is Verdict.AUTHORIZED:
        raise MirrorLoopMismatch("authorized actions cannot enter a mirror loop")
    if decision.proposal_id != proposal.id:
        raise MirrorLoopMismatch("decision does not belong to proposal")
    if not decision.policy_fingerprint or decision.policy_fingerprint != policy_fingerprint:
        raise MirrorLoopMismatch("decision does not belong to policy")
    if not execution_id:
        raise ValueError("execution_id must be non-empty")
    return MirrorLoop(
        proposal_fingerprint=proposal.fingerprint(),
        policy_fingerprint=policy_fingerprint,
        execution_id=execution_id,
        policy=mirror_policy,
        monotonic_ns=monotonic_ns,
    )
