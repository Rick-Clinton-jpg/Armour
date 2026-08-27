"""Offline mutation testing for Armour policies and verifier chains.

This module never executes a proposal. It challenges the gate with bounded,
named adversarial variants and reports which safety invariants were actually
exercised and which mutants survived.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from .gate import ArmourGate
from .models import ActionProposal, Effect, Risk, Verdict
from .policy import Policy


MutationTransform = Callable[[ActionProposal], ActionProposal]


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
        mutations: Iterable[Mutation],
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
            mutant = mutation.transform(baseline)
            if not isinstance(mutant, ActionProposal):
                raise TypeError(f"mutation {mutation.id!r} did not return ActionProposal")
            decision = self.gate.evaluate(
                mutant,
                request_risk=mutation.request_risk or request_risk,
            )
            outcomes.append(
                MutationOutcome(
                    mutation_id=mutation.id,
                    invariant=mutation.invariant,
                    description=mutation.description,
                    verdict=decision.verdict,
                    killed=decision.verdict in mutation.expected_verdicts,
                    reasons=decision.reasons,
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
    }
)


def standard_mutant_family(
    baseline: ActionProposal, policy: Policy
) -> tuple[Mutation, ...]:
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
    return tuple(mutations)
