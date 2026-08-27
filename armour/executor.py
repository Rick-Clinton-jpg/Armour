"""Execution broker: only registered host functions can cross the boundary."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .audit import ReceiptLog
from .gate import ArmourGate
from .models import ActionProposal, ExecutionOutcome, HumanApproval, Risk, Verdict


Handler = Callable[[ActionProposal], Any]


class GuardedExecutor:
    def __init__(self, gate: ArmourGate, receipts: ReceiptLog | None = None):
        self.gate = gate
        self.receipts = receipts
        self._handlers: dict[str, Handler] = {}

    def register(self, action: str, handler: Handler) -> None:
        if action not in self.gate.policy.allowed_actions:
            raise ValueError(f"cannot register action absent from policy: {action!r}")
        if action in self._handlers:
            raise ValueError(f"action already registered: {action!r}")
        self._handlers[action] = handler

    def execute(
        self,
        proposal: ActionProposal,
        *,
        request_risk: Risk = Risk.LOW,
        approval: HumanApproval | None = None,
    ) -> ExecutionOutcome:
        decision = self.gate.evaluate(
            proposal,
            request_risk=request_risk,
            approval=approval,
            consume_approval=True,
        )
        if decision.verdict is not Verdict.AUTHORIZED:
            outcome = ExecutionOutcome(
                proposal.id, False, error=f"Armour decision: {decision.verdict.value}"
            )
        elif proposal.action not in self._handlers:
            outcome = ExecutionOutcome(
                proposal.id, False, error="authorized action has no registered handler"
            )
        else:
            try:
                output = self._handlers[proposal.action](proposal)
                outcome = ExecutionOutcome(proposal.id, True, output=output)
            except Exception as exc:
                outcome = ExecutionOutcome(
                    proposal.id, False, error=f"{type(exc).__name__}: {exc}"
                )
        if self.receipts:
            self.receipts.append(proposal, decision, outcome)
        return outcome
