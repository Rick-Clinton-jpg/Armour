"""Offline mutation testing for Armour policies and verifier chains.

This module never executes a proposal. It challenges the gate and selected
fail-closed construction/storage/binding boundaries with bounded, named
adversarial variants, then reports which safety invariants were exercised and
which mutants survived.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
import shutil
import sqlite3
import ssl
import tempfile
from typing import Callable, Iterable

from .approvals import HMACApprovalVerifier
from .binding import BindingError, DependencyPolicy, prepare_execution_binding
from .gate import ArmourGate
from .ledger import (
    ApprovalLedgerError,
    InMemoryApprovalLedger,
    SQLiteApprovalLedger,
)
from .memory_sandbox import RememberingGate, SecurityMemorySandbox
from .mirror_loop import (
    MirrorLoopMismatch,
    MirrorLoopPolicy,
    MirrorLoopTerminated,
    prepare_mirror_loop,
)
from .models import ActionProposal, Effect, HumanApproval, Risk, Verdict
from .network_binding import NetworkBinder
from .policy import Policy
from .security_memory import (
    SecurityMemoryError,
    SQLiteIncidentMemory,
    SQLiteMutantMemory,
)


MutationTransform = Callable[[ActionProposal], ActionProposal]
BoundaryProbe = Callable[[ArmourGate, ActionProposal], "BoundaryProbeResult"]


@dataclass(frozen=True, slots=True)
class Mutation:
    id: str
    description: str
    invariant: str
    transform: MutationTransform
    expected_verdicts: frozenset[Verdict] = frozenset(
        {Verdict.REJECTED, Verdict.ESCALATED}
    )
    request_risk: Risk | None = None


@dataclass(frozen=True, slots=True)
class BoundaryProbeResult:
    """A verdict-shaped result from a non-executing boundary challenge."""

    verdict: Verdict
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BoundaryMutation:
    """Offline lifecycle/storage/binding attack that never invokes a handler."""

    id: str
    description: str
    invariant: str
    probe: BoundaryProbe
    expected_verdicts: frozenset[Verdict] = frozenset(
        {Verdict.REJECTED, Verdict.ESCALATED}
    )


@dataclass(frozen=True, slots=True)
class MutationOutcome:
    mutation_id: str
    invariant: str
    description: str
    verdict: Verdict
    killed: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MutationReport:
    baseline_verdict: Verdict
    outcomes: tuple[MutationOutcome, ...]
    required_invariants: frozenset[str]
    threshold: float = 1.0

    @property
    def mutation_score(self) -> float:
        if not self.outcomes:
            return 0.0
        return sum(outcome.killed for outcome in self.outcomes) / len(self.outcomes)

    @property
    def exercised_invariants(self) -> frozenset[str]:
        return frozenset(outcome.invariant for outcome in self.outcomes)

    @property
    def invariant_coverage(self) -> float:
        if not self.required_invariants:
            return 1.0
        return len(self.exercised_invariants & self.required_invariants) / len(
            self.required_invariants
        )

    @property
    def uncovered_invariants(self) -> frozenset[str]:
        return self.required_invariants - self.exercised_invariants

    @property
    def unprotected_invariants(self) -> frozenset[str]:
        return frozenset(outcome.invariant for outcome in self.outcomes if not outcome.killed)

    @property
    def surviving_mutants(self) -> tuple[MutationOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.killed)

    @property
    def passed(self) -> bool:
        return (
            self.baseline_verdict is Verdict.AUTHORIZED
            and self.invariant_coverage == 1.0
            and self.mutation_score >= self.threshold
            and not self.unprotected_invariants
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "baseline_verdict": self.baseline_verdict.value,
            "mutation_score": self.mutation_score,
            "invariant_coverage": self.invariant_coverage,
            "threshold": self.threshold,
            "passed": self.passed,
            "required_invariants": sorted(self.required_invariants),
            "exercised_invariants": sorted(self.exercised_invariants),
            "uncovered_invariants": sorted(self.uncovered_invariants),
            "unprotected_invariants": sorted(self.unprotected_invariants),
            "outcomes": [
                {
                    "id": outcome.mutation_id,
                    "invariant": outcome.invariant,
                    "description": outcome.description,
                    "verdict": outcome.verdict.value,
                    "killed": outcome.killed,
                    "reasons": list(outcome.reasons),
                }
                for outcome in self.outcomes
            ],
        }


class MutationRunner:
    def __init__(
        self,
        gate: ArmourGate,
        *,
        required_invariants: Iterable[str],
        threshold: float = 1.0,
    ):
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("mutation threshold must be between 0 and 1")
        self.gate = gate
        self.required_invariants = frozenset(required_invariants)
        self.threshold = threshold

    def run(
        self,
        baseline: ActionProposal,
        mutations: Iterable[Mutation | BoundaryMutation],
        *,
        request_risk: Risk = Risk.LOW,
    ) -> MutationReport:
        baseline_decision = self.gate.evaluate(baseline, request_risk=request_risk)
        outcomes: list[MutationOutcome] = []
        seen_ids: set[str] = set()
        for mutation in mutations:
            if mutation.id in seen_ids:
                raise ValueError(f"duplicate mutation id: {mutation.id!r}")
            seen_ids.add(mutation.id)
            if isinstance(mutation, Mutation):
                mutant = mutation.transform(baseline)
                if not isinstance(mutant, ActionProposal):
                    raise TypeError(
                        f"mutation {mutation.id!r} did not return ActionProposal"
                    )
                decision = self.gate.evaluate(
                    mutant,
                    request_risk=mutation.request_risk or request_risk,
                )
                verdict = decision.verdict
                reasons = decision.reasons
            elif isinstance(mutation, BoundaryMutation):
                try:
                    result = mutation.probe(self.gate, baseline)
                except Exception as exc:
                    # A broken probe is evidence of nothing. Treat it as a
                    # survivor instead of accidentally counting an arbitrary
                    # exception as a successful fail-closed rejection.
                    result = BoundaryProbeResult(
                        Verdict.AUTHORIZED,
                        (f"boundary probe failed unexpectedly: {type(exc).__name__}",),
                    )
                if not isinstance(result, BoundaryProbeResult):
                    raise TypeError(
                        f"boundary mutation {mutation.id!r} returned an invalid result"
                    )
                verdict = result.verdict
                reasons = result.reasons
            else:
                raise TypeError("mutations must be Mutation or BoundaryMutation values")
            outcomes.append(
                MutationOutcome(
                    mutation_id=mutation.id,
                    invariant=mutation.invariant,
                    description=mutation.description,
                    verdict=verdict,
                    killed=verdict in mutation.expected_verdicts,
                    reasons=reasons,
                )
            )
        return MutationReport(
            baseline_verdict=baseline_decision.verdict,
            outcomes=tuple(outcomes),
            required_invariants=self.required_invariants,
            threshold=self.threshold,
        )


STANDARD_INVARIANTS = frozenset(
    {
        "action_allowlist",
        "effect_policy",
        "filesystem_scope",
        "network_policy",
        "dangerous_content",
        "risk_monotonicity",
        "production_isolated_signing",
        "production_durable_ledger",
        "production_ledger_integrity",
        "production_action_schemas",
        "approval_lifetime_ceiling",
        "approval_ledger_row_integrity",
        "approval_ledger_nonce_durability",
        "approval_ledger_rollback_detection",
        "approval_ledger_key_integrity",
        "approval_ledger_capacity",
        "network_destination_binding",
        "network_public_destination",
        "network_method_binding",
        "network_tls_authentication",
        "binding_freshness_ceiling",
        "security_memory_integrity",
        "security_memory_quarantine",
        "security_memory_review_gate",
        "mirror_authorization_boundary",
        "mirror_scope_binding",
        "mirror_resource_bounds",
        "mirror_absolute_ceiling",
        "mirror_display_safety",
        "mirror_exact_input_type",
    }
)


def _expected_failure(
    operation: Callable[[], object],
    expected: type[Exception] | tuple[type[Exception], ...],
    reason: str,
) -> BoundaryProbeResult:
    """Count only the intended fail-closed exception as a killed mutant."""

    try:
        operation()
    except expected:
        return BoundaryProbeResult(Verdict.REJECTED, (reason,))
    except Exception as exc:
        return BoundaryProbeResult(
            Verdict.AUTHORIZED,
            (f"unexpected failure did not prove invariant: {type(exc).__name__}",),
        )
    return BoundaryProbeResult(
        Verdict.AUTHORIZED, ("attack was accepted by the challenged boundary",)
    )


class _IsolatedVerifier:
    signing_authority_isolated = True

    def verify(self, _approval: HumanApproval) -> bool:
        return False


class _DurableLedger:
    durable = True

    def __init__(self, *, integrity_protected: bool) -> None:
        self.integrity_protected = integrity_protected

    def claim(self, _approval: HumanApproval) -> bool:
        return True


class _Checkpoint:
    def __init__(self) -> None:
        self.generation: int | None = None

    def read_generation(self, _namespace: str) -> int | None:
        return self.generation

    def advance_generation(self, _namespace: str, generation: int) -> None:
        current = -1 if self.generation is None else self.generation
        self.generation = max(current, generation)


class _ProbeResponse:
    status = 200
    reason = "OK"

    def read(self, _amount: int) -> bytes:
        return b"probe"

    def getheaders(self) -> list[tuple[str, str]]:
        return []


class _ProbeConnection:
    def __init__(self, destination_ip: str) -> None:
        self.destination_ip = destination_ip
        self.requests: list[tuple[str, str]] = []

    def request(self, method: str, target: str) -> None:
        self.requests.append((method, target))

    def getresponse(self) -> _ProbeResponse:
        return _ProbeResponse()

    def close(self) -> None:
        pass


class _ProbeNetworkBinder(NetworkBinder):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.destinations: list[str] = []

    def _open_connection(
        self,
        *,
        scheme: str,
        hostname: str,
        destination_ip: str,
        port: int,
    ) -> _ProbeConnection:
        del scheme, hostname, port
        self.destinations.append(destination_ip)
        return _ProbeConnection(destination_ip)


def _production_non_isolated_probe(
    gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    verifier = HMACApprovalVerifier({"local": b"shared-secret"})
    return _expected_failure(
        lambda: ArmourGate.production(
            gate.policy,
            approval_verifier=verifier,
            approval_ledger=_DurableLedger(integrity_protected=True),
        ),
        ValueError,
        "production rejected evaluator-local signing authority",
    )


def _production_non_durable_probe(
    gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    return _expected_failure(
        lambda: ArmourGate.production(
            gate.policy,
            approval_verifier=_IsolatedVerifier(),
            approval_ledger=InMemoryApprovalLedger(),
        ),
        ValueError,
        "production rejected a non-durable approval ledger",
    )


def _production_unprotected_probe(
    gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    return _expected_failure(
        lambda: ArmourGate.production(
            gate.policy,
            approval_verifier=_IsolatedVerifier(),
            approval_ledger=_DurableLedger(integrity_protected=False),
        ),
        ValueError,
        "production rejected a ledger without integrity protection",
    )


def _production_missing_schema_probe(
    gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    return _expected_failure(
        lambda: ArmourGate.production(
            replace(gate.policy, action_schemas={}),
            approval_verifier=_IsolatedVerifier(),
            approval_ledger=_DurableLedger(integrity_protected=True),
        ),
        ValueError,
        "production rejected an allowed action without a strict schema",
    )


def _approval_lifetime_ceiling_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    return _expected_failure(
        lambda: HumanApproval.issue(
            baseline,
            policy_fingerprint=gate.policy.fingerprint(),
            approved_by="offline-mutation-harness",
            ttl_seconds=3_601,
        ),
        ValueError,
        "approval issuance rejected a lifetime above the hard ceiling",
    )


def _approval(baseline: ActionProposal, policy: Policy, nonce: str) -> HumanApproval:
    approval = HumanApproval.issue(
        baseline,
        policy_fingerprint=policy.fingerprint(),
        approved_by="offline-mutation-harness",
        key_id="probe",
    )
    return HumanApproval(
        proposal_id=approval.proposal_id,
        proposal_fingerprint=approval.proposal_fingerprint,
        policy_fingerprint=approval.policy_fingerprint,
        approved_by=approval.approved_by,
        expires_at=approval.expires_at,
        nonce=nonce,
        timestamp=approval.timestamp,
        key_id=approval.key_id,
    )


def _ledger_capacity_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    def attack() -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = SQLiteApprovalLedger(
                Path(directory) / "ledger.sqlite3",
                integrity_key=b"c" * 32,
                max_claims=1,
            )
            ledger.claim(_approval(baseline, gate.policy, "capacity-first"))
            ledger.claim(_approval(baseline, gate.policy, "capacity-overflow"))

    return _expected_failure(
        attack,
        ApprovalLedgerError,
        "approval ledger rejected growth beyond its configured capacity",
    )


def _network_insecure_tls_probe(
    _gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    return _expected_failure(
        lambda: NetworkBinder(ssl_context=ssl._create_unverified_context()),
        ValueError,
        "network binder rejected disabled TLS authentication",
    )


def _ledger_row_tamper_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    def attack() -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite3"
            ledger = SQLiteApprovalLedger(path, integrity_key=b"r" * 32)
            ledger.claim(_approval(baseline, gate.policy, "row-tamper"))
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE approval_claims SET approved_by = 'attacker'"
                )
                connection.commit()
            ledger.claims()

    return _expected_failure(
        attack, ApprovalLedgerError, "approval ledger detected row tampering"
    )


def _ledger_nonce_deletion_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    def attack() -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite3"
            ledger = SQLiteApprovalLedger(path, integrity_key=b"d" * 32)
            ledger.claim(_approval(baseline, gate.policy, "deleted-nonce"))
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("DELETE FROM approval_claims")
                connection.commit()
            ledger.claims()

    return _expected_failure(
        attack, ApprovalLedgerError, "approval ledger detected nonce deletion"
    )


def _ledger_rollback_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    def attack() -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite3"
            snapshot = Path(directory) / "old.sqlite3"
            checkpoint = _Checkpoint()
            ledger = SQLiteApprovalLedger(
                path, integrity_key=b"b" * 32, checkpoint=checkpoint
            )
            ledger.claim(_approval(baseline, gate.policy, "rollback-one"))
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            shutil.copyfile(path, snapshot)
            ledger.claim(_approval(baseline, gate.policy, "rollback-two"))
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            shutil.copyfile(snapshot, path)
            SQLiteApprovalLedger(
                path, integrity_key=b"b" * 32, checkpoint=checkpoint
            )

    return _expected_failure(
        attack, ApprovalLedgerError, "external checkpoint detected ledger rollback"
    )


def _ledger_wrong_key_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    def attack() -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite3"
            ledger = SQLiteApprovalLedger(path, integrity_key=b"k" * 32)
            ledger.claim(_approval(baseline, gate.policy, "wrong-key"))
            SQLiteApprovalLedger(path, integrity_key=b"x" * 32)

    return _expected_failure(
        attack, ApprovalLedgerError, "approval ledger rejected the wrong integrity key"
    )


def _network_policy() -> Policy:
    return Policy(
        allowed_actions=frozenset({"fetch"}),
        action_effects={"fetch": Effect.READ_ONLY},
        action_dependencies={
            "fetch": {"network": DependencyPolicy("network", max_age_ms=50)}
        },
        policy_id="offline-network-probes",
    )


def _network_destination_substitution_probe(
    _gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    addresses = ["93.184.216.34"]
    policy = _network_policy()
    proposal = ActionProposal(
        "fetch", Effect.READ_ONLY, Risk.LOW,
        resource="https://example.com/data", method="GET",
    )
    binder = _ProbeNetworkBinder(resolver=lambda _host: tuple(addresses))
    binding = prepare_execution_binding(
        proposal,
        policy,
        execution_id="network-probe",
        binders={"network": binder},
        monotonic_ns=lambda: 1_000_000_000,
    )
    try:
        addresses[:] = ["1.1.1.1"]
        context = binding.consume(
            proposal=proposal,
            policy_fingerprint=policy.fingerprint(),
            execution_id="network-probe",
        )
        try:
            response = context.capability("network").request()
        finally:
            context.close()
    finally:
        binding.close()
    if response.destination_ip == "93.184.216.34" and binder.destinations == [
        "93.184.216.34"
    ]:
        return BoundaryProbeResult(
            Verdict.REJECTED,
            ("post-binding DNS substitution could not redirect the request",),
        )
    return BoundaryProbeResult(
        Verdict.AUTHORIZED, ("post-binding DNS substitution redirected the request",)
    )


def _network_private_probe(
    _gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    policy = _network_policy()
    proposal = ActionProposal(
        "fetch", Effect.READ_ONLY, Risk.LOW,
        resource="http://127.0.0.1/private", method="GET",
    )
    return _expected_failure(
        lambda: prepare_execution_binding(
            proposal,
            policy,
            execution_id="private-probe",
            binders={"network": _ProbeNetworkBinder()},
            monotonic_ns=lambda: 1_000_000_000,
        ),
        BindingError,
        "network binder rejected a private resolved destination",
    )


def _network_method_probe(
    _gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    policy = _network_policy()
    proposal = ActionProposal(
        "fetch", Effect.READ_ONLY, Risk.LOW,
        resource="https://example.com/data", method="POST",
    )
    return _expected_failure(
        lambda: prepare_execution_binding(
            proposal,
            policy,
            execution_id="method-probe",
            binders={
                "network": _ProbeNetworkBinder(
                    resolver=lambda _host: ("93.184.216.34",)
                )
            },
            monotonic_ns=lambda: 1_000_000_000,
        ),
        BindingError,
        "network binder rejected method confusion",
    )


def _binding_freshness_ceiling_probe(
    _gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    return _expected_failure(
        lambda: DependencyPolicy("filesystem", max_age_ms=60_001),
        ValueError,
        "execution binding rejected a deadline above its freshness ceiling",
    )


def _memory_integrity_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    def attack() -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.sqlite3"
            memory = SQLiteIncidentMemory(path, integrity_key=b"m" * 32)
            remembering = RememberingGate(gate, memory, rejection_threshold=2)
            attack_proposal = ActionProposal(
                f"{baseline.action}_unknown", Effect.READ_ONLY, Risk.LOW
            )
            remembering.evaluate(attack_proposal, subject_id="probe-agent")
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE security_incidents SET subject_id = 'attacker'"
                )
                connection.commit()
            remembering.evaluate(baseline, subject_id="probe-agent")

    return _expected_failure(
        attack, SecurityMemoryError, "security memory detected row tampering"
    )


def _memory_quarantine_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    with tempfile.TemporaryDirectory() as directory:
        memory = SQLiteIncidentMemory(
            Path(directory) / "memory.sqlite3", integrity_key=b"q" * 32
        )
        remembering = RememberingGate(gate, memory, rejection_threshold=1)
        attack = ActionProposal(
            f"{baseline.action}_unknown", Effect.READ_ONLY, Risk.LOW
        )
        remembering.evaluate(attack, subject_id="probe-agent")
        decision = remembering.evaluate(baseline, subject_id="probe-agent")
    if decision.verdict is Verdict.REJECTED and any(
        "quarantined" in reason for reason in decision.reasons
    ):
        return BoundaryProbeResult(decision.verdict, decision.reasons)
    return BoundaryProbeResult(
        Verdict.AUTHORIZED, ("repeated rejection did not trigger quarantine",)
    )


def _memory_review_gate_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    def attack() -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.sqlite3"
            remembering = RememberingGate(
                gate,
                SQLiteIncidentMemory(path, integrity_key=b"v" * 32),
            )
            sandbox = SecurityMemorySandbox(
                remembering,
                SQLiteMutantMemory(path, integrity_key=b"v" * 32),
            )
            sandbox.promote(
                "unobserved", baseline, promoted_by="offline-mutation-harness"
            )

    return _expected_failure(
        attack, ValueError, "unobserved proposal could not enter mutant memory"
    )


def _mirror_authorized_diversion_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    decision = gate.evaluate(baseline)
    return _expected_failure(
        lambda: prepare_mirror_loop(
            baseline,
            decision,
            policy_fingerprint=gate.policy.fingerprint(),
            execution_id="mirror-probe",
            mirror_policy=MirrorLoopPolicy(),
        ),
        MirrorLoopMismatch,
        "authorized proposal could not be diverted into deception",
    )


def _mirror_scope_substitution_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    rejected = ActionProposal(
        f"{baseline.action}_unknown", Effect.DESTRUCTIVE, Risk.CRITICAL
    )
    decision = gate.evaluate(rejected)
    chamber = prepare_mirror_loop(
        rejected,
        decision,
        policy_fingerprint=gate.policy.fingerprint(),
        execution_id="mirror-probe",
        mirror_policy=MirrorLoopPolicy(),
        monotonic_ns=lambda: 1_000_000_000,
    )
    return _expected_failure(
        lambda: chamber.submit(
            "attempt",
            proposal=rejected,
            policy_fingerprint=gate.policy.fingerprint(),
            execution_id="substituted-execution",
        ),
        MirrorLoopMismatch,
        "mirror loop rejected cross-execution substitution",
    )


def _mirror_resource_exhaustion_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    rejected = ActionProposal(
        f"{baseline.action}_unknown", Effect.DESTRUCTIVE, Risk.CRITICAL
    )
    decision = gate.evaluate(rejected)
    chamber = prepare_mirror_loop(
        rejected,
        decision,
        policy_fingerprint=gate.policy.fingerprint(),
        execution_id="mirror-budget-probe",
        mirror_policy=MirrorLoopPolicy(max_steps=1, repeat_limit=2),
        monotonic_ns=lambda: 1_000_000_000,
    )
    chamber.submit(
        "first attempt",
        proposal=rejected,
        policy_fingerprint=gate.policy.fingerprint(),
        execution_id="mirror-budget-probe",
    )
    return _expected_failure(
        lambda: chamber.submit(
            "second attempt",
            proposal=rejected,
            policy_fingerprint=gate.policy.fingerprint(),
            execution_id="mirror-budget-probe",
        ),
        MirrorLoopTerminated,
        "mirror loop enforced its host-owned step budget",
    )


def _mirror_absolute_ceiling_probe(
    _gate: ArmourGate, _baseline: ActionProposal
) -> BoundaryProbeResult:
    return _expected_failure(
        lambda: MirrorLoopPolicy(max_steps=65),
        ValueError,
        "mirror loop rejected configuration above its absolute step ceiling",
    )


def _mirror_display_safety_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    rejected = ActionProposal(
        f"{baseline.action}_unknown", Effect.DESTRUCTIVE, Risk.CRITICAL
    )
    decision = gate.evaluate(rejected)
    chamber = prepare_mirror_loop(
        rejected,
        decision,
        policy_fingerprint=gate.policy.fingerprint(),
        execution_id="mirror-display-probe",
        mirror_policy=MirrorLoopPolicy(),
        monotonic_ns=lambda: 1_000_000_000,
    )
    observation = chamber.submit(
        "safe\x1b[2J\x9b31m\x7f\u202etext",
        proposal=rejected,
        policy_fingerprint=gate.policy.fingerprint(),
        execution_id="mirror-display-probe",
    )
    displayed = observation.reflection.display_text
    if all(character.isprintable() for character in displayed) and all(
        token in displayed for token in ("<U+001B>", "<U+009B>", "<U+007F>", "<U+202E>")
    ):
        return BoundaryProbeResult(
            Verdict.REJECTED,
            ("mirror loop neutralized terminal and Unicode controls",),
        )
    return BoundaryProbeResult(
        Verdict.AUTHORIZED,
        ("mirror loop returned active terminal or Unicode controls",),
    )


def _mirror_input_subclass_probe(
    gate: ArmourGate, baseline: ActionProposal
) -> BoundaryProbeResult:
    called = False

    class HostileString(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            nonlocal called
            called = True
            return super().encode(*args, **kwargs)

    rejected = ActionProposal(
        f"{baseline.action}_unknown", Effect.DESTRUCTIVE, Risk.CRITICAL
    )
    decision = gate.evaluate(rejected)
    chamber = prepare_mirror_loop(
        rejected,
        decision,
        policy_fingerprint=gate.policy.fingerprint(),
        execution_id="mirror-input-probe",
        mirror_policy=MirrorLoopPolicy(),
        monotonic_ns=lambda: 1_000_000_000,
    )
    try:
        chamber.submit(
            HostileString("attempt"),
            proposal=rejected,
            policy_fingerprint=gate.policy.fingerprint(),
            execution_id="mirror-input-probe",
        )
    except MirrorLoopTerminated:
        if not called:
            return BoundaryProbeResult(
                Verdict.REJECTED,
                ("mirror loop rejected a string subclass before method dispatch",),
            )
    return BoundaryProbeResult(
        Verdict.AUTHORIZED,
        ("mirror loop invoked or accepted a string-subclass method",),
    )


def standard_mutant_family(
    baseline: ActionProposal, policy: Policy
) -> tuple[Mutation | BoundaryMutation, ...]:
    """Create a bounded, deterministic family for a representative proposal."""

    def changed(**updates) -> ActionProposal:
        values = {
            "action": baseline.action,
            "effect": baseline.effect,
            "risk": baseline.risk,
            "resource": baseline.resource,
            "method": baseline.method,
            "payload": baseline.payload_data(),
            "id": baseline.id,
        }
        values.update(updates)
        return ActionProposal(**values)

    mutations: list[Mutation] = [
        Mutation(
            "unknown-action",
            "replace a registered action with an invented one",
            "action_allowlist",
            lambda _: changed(action=f"{baseline.action}_unregistered"),
            frozenset({Verdict.REJECTED}),
        ),
        Mutation(
            "forbidden-effect",
            "declare an irreversible effect",
            "effect_policy",
            lambda _: changed(effect=Effect.IRREVERSIBLE, risk=Risk.LOW),
            frozenset({Verdict.REJECTED}),
        ),
        Mutation(
            "root-escape",
            "replace the resource with a path outside configured roots",
            "filesystem_scope",
            lambda _: changed(resource="/etc/passwd"),
            frozenset({Verdict.REJECTED}),
        ),
        Mutation(
            "private-network",
            "replace the resource with a loopback URL",
            "network_policy",
            lambda _: changed(resource="http://127.0.0.1/internal"),
            frozenset({Verdict.REJECTED}),
        ),
        Mutation(
            "command-injection",
            "insert a destructive command signature into nested arguments",
            "dangerous_content",
            lambda _: changed(payload={**baseline.payload_data(), "command": "rm -rf /"}),
            frozenset({Verdict.REJECTED}),
        ),
        Mutation(
            "request-risk-downgrade",
            "claim low candidate risk under a high-risk request",
            "risk_monotonicity",
            lambda _: changed(risk=Risk.LOW),
            frozenset({Verdict.ESCALATED}),
            request_risk=Risk.HIGH,
        ),
    ]

    destructive_actions = sorted(
        action
        for action, effect in policy.action_effects.items()
        if effect in {Effect.DESTRUCTIVE, Effect.IRREVERSIBLE}
    )
    if destructive_actions:
        action = destructive_actions[0]
        mutations.append(
            Mutation(
                "under-declared-action-effect",
                "label a policy-known destructive action as read-only and low-risk",
                "effect_policy",
                lambda _, action=action: changed(
                    action=action,
                    effect=Effect.READ_ONLY,
                    risk=Risk.LOW,
                    resource=None,
                ),
            )
        )

    mutations.extend(
        (
            BoundaryMutation(
                "production-non-isolated-verifier",
                "attempt production construction with evaluator-local HMAC signing",
                "production_isolated_signing",
                _production_non_isolated_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "production-non-durable-ledger",
                "attempt production construction with process-local replay state",
                "production_durable_ledger",
                _production_non_durable_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "production-unprotected-ledger",
                "attempt production construction without ledger authentication",
                "production_ledger_integrity",
                _production_unprotected_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "production-missing-action-schema",
                "attempt production construction with an unstructured action payload",
                "production_action_schemas",
                _production_missing_schema_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "approval-excessive-signed-lifetime",
                "issue an approval beyond Armour's absolute lifetime ceiling",
                "approval_lifetime_ceiling",
                _approval_lifetime_ceiling_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "approval-ledger-row-tamper",
                "rewrite a claimed approval row behind the integrity seal",
                "approval_ledger_row_integrity",
                _ledger_row_tamper_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "approval-ledger-nonce-deletion",
                "delete consumed nonces from durable replay history",
                "approval_ledger_nonce_durability",
                _ledger_nonce_deletion_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "approval-ledger-valid-rollback",
                "replace the ledger with an older internally valid snapshot",
                "approval_ledger_rollback_detection",
                _ledger_rollback_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "approval-ledger-wrong-integrity-key",
                "open protected replay state with a different integrity key",
                "approval_ledger_key_integrity",
                _ledger_wrong_key_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "approval-ledger-capacity-exhaustion",
                "grow authenticated replay state beyond its configured hard capacity",
                "approval_ledger_capacity",
                _ledger_capacity_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "network-destination-substitution",
                "change DNS after binding preparation",
                "network_destination_binding",
                _network_destination_substitution_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "network-private-destination",
                "bind a request to a loopback address",
                "network_public_destination",
                _network_private_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "network-method-confusion",
                "present a state-changing method to the read-only binder",
                "network_method_binding",
                _network_method_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "network-insecure-tls-context",
                "disable certificate and hostname verification on the network binder",
                "network_tls_authentication",
                _network_insecure_tls_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "binding-excessive-freshness-window",
                "configure execution binding above Armour's freshness ceiling",
                "binding_freshness_ceiling",
                _binding_freshness_ceiling_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "security-memory-row-tamper",
                "rewrite a recorded incident behind its integrity seal",
                "security_memory_integrity",
                _memory_integrity_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "security-memory-quarantine-evasion",
                "retry a safe action after the subject reached quarantine threshold",
                "security_memory_quarantine",
                _memory_quarantine_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "security-memory-unreviewed-promotion",
                "promote a proposal that has no observed rejected incident",
                "security_memory_review_gate",
                _memory_review_gate_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "mirror-authorized-diversion",
                "divert an authorized proposal into the deception chamber",
                "mirror_authorization_boundary",
                _mirror_authorized_diversion_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "mirror-scope-substitution",
                "transplant a mirror session into another execution",
                "mirror_scope_binding",
                _mirror_scope_substitution_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "mirror-resource-exhaustion",
                "continue submitting attempts after the host-owned step ceiling",
                "mirror_resource_bounds",
                _mirror_resource_exhaustion_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "mirror-absolute-ceiling",
                "configure the deception chamber above Armour's hard step ceiling",
                "mirror_absolute_ceiling",
                _mirror_absolute_ceiling_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "mirror-terminal-control-reflection",
                "reflect active terminal, Unicode, and display-control characters",
                "mirror_display_safety",
                _mirror_display_safety_probe,
                frozenset({Verdict.REJECTED}),
            ),
            BoundaryMutation(
                "mirror-hostile-string-subclass",
                "supply a string subclass with an attacker-controlled encode method",
                "mirror_exact_input_type",
                _mirror_input_subclass_probe,
                frozenset({Verdict.REJECTED}),
            ),
        )
    )
    return tuple(mutations)
