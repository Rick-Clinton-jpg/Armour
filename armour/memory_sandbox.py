"""Experimental evaluation sandbox for Armour's two security memories.

This is a policy/mutation harness, not an operating-system containment sandbox.
It never executes registered handlers.
"""

from __future__ import annotations

from dataclasses import replace
import time
from typing import Callable

from .gate import ArmourGate
from .models import ActionProposal, CheckResult, Decision, HumanApproval, Risk, Verdict
from .security_memory import (
    IncidentMemory,
    RememberedMutant,
    RememberedMutantReport,
    SQLiteMutantMemory,
)


class RememberingGate:
    """Gate wrapper whose memory can tighten, never loosen, base policy."""

    def __init__(
        self,
        gate: ArmourGate,
        incident_memory: IncidentMemory,
        *,
        rejection_threshold: int = 3,
        window_seconds: float = 300,
        wall_clock: Callable[[], float] = time.time,
    ):
        if rejection_threshold < 1:
            raise ValueError("rejection_threshold must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if not incident_memory.durable:
            raise ValueError("remembering gate requires durable incident memory")
        self.gate = gate
        self.incident_memory = incident_memory
        self.rejection_threshold = rejection_threshold
        self.window_seconds = window_seconds
        self._wall_clock = wall_clock

    def evaluate(
        self,
        proposal: ActionProposal,
        *,
        subject_id: str,
        request_risk: Risk = Risk.LOW,
        approval: HumanApproval | None = None,
        consume_approval: bool = True,
    ) -> Decision:
        since = self._wall_clock() - self.window_seconds
        prior_rejections = self.incident_memory.rejection_count(subject_id, since=since)
        if prior_rejections >= self.rejection_threshold:
            # Still run Armour's mandatory checks for evidence, but never consume
            # an approval for an execution the quarantine will reject.
            decision = self.gate.evaluate(
                proposal,
                request_risk=request_risk,
                approval=approval,
                consume_approval=False,
            )
            reason = (
                f"subject quarantined after {prior_rejections} rejected proposals "
                f"within {self.window_seconds:g} seconds"
            )
            memory_check = CheckResult(
                "incident_memory", False, (reason,), Risk.HIGH
            )
            return replace(
                decision,
                verdict=Verdict.REJECTED,
                effective_risk=max(decision.effective_risk, Risk.HIGH),
                checks=decision.checks + (memory_check,),
                reasons=decision.reasons + (reason,),
                human_approved=False,
                approved_by=None,
                approval_nonce=None,
            )

        decision = self.gate.evaluate(
            proposal,
            request_risk=request_risk,
            approval=approval,
            consume_approval=consume_approval,
        )
        if decision.verdict is Verdict.REJECTED:
            self.incident_memory.record_rejection(subject_id, proposal, decision)
        return decision


class SecurityMemorySandbox:
    """Offline harness joining incident observation and reviewed mutant memory."""

    def __init__(self, gate: RememberingGate, mutant_memory: SQLiteMutantMemory):
        self.gate = gate
        self.mutant_memory = mutant_memory

    def observe(self, subject_id: str, proposal: ActionProposal) -> Decision:
        return self.gate.evaluate(proposal, subject_id=subject_id)

    def promote(
        self, name: str, proposal: ActionProposal, *, promoted_by: str
    ) -> RememberedMutant:
        incidents = tuple(
            incident
            for incident in self.gate.incident_memory.incidents()
            if incident.proposal_fingerprint == proposal.fingerprint()
        )
        if not incidents:
            raise ValueError("only an observed rejection can be promoted")
        incident = incidents[-1]
        return self.mutant_memory.remember(
            name,
            proposal,
            expected_verdicts=frozenset({Verdict.REJECTED}),
            policy_fingerprint=incident.policy_fingerprint,
            promoted_by=promoted_by,
            source_incident_id=incident.id,
        )

    def replay(self, gate: ArmourGate | None = None) -> RememberedMutantReport:
        return self.mutant_memory.run(gate or self.gate.gate)
