"""Execution broker: only registered host functions can cross the boundary."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import time
from typing import Any
from uuid import uuid4

from .audit import ReceiptLog
from .binding import (
    BindingError,
    BindingExpired,
    DependencyBinder,
    ExecutionBinding,
    prepare_execution_binding,
)
from .gate import ArmourGate
from .models import (
    ActionProposal,
    AuditStatus,
    ExecutionOutcome,
    HumanApproval,
    Risk,
    Verdict,
)


Handler = Callable[[ActionProposal], Any]
BoundHandler = Callable[[ActionProposal, Any], Any]


class GuardedExecutor:
    def __init__(
        self,
        gate: ArmourGate,
        receipts: ReceiptLog | None = None,
        *,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ):
        self.gate = gate
        self.receipts = receipts
        self._monotonic_ns = monotonic_ns
        self._handlers: dict[str, Handler] = {}
        self._bound_handlers: dict[
            str, tuple[BoundHandler, dict[str, DependencyBinder]]
        ] = {}

    def register(self, action: str, handler: Handler) -> None:
        if action not in self.gate.policy.allowed_actions:
            raise ValueError(f"cannot register action absent from policy: {action!r}")
        if self.gate.policy.action_dependencies.get(action):
            raise ValueError(f"action requires execution binding: {action!r}")
        if action in self._handlers or action in self._bound_handlers:
            raise ValueError(f"action already registered: {action!r}")
        self._handlers[action] = handler

    def register_bound(
        self,
        action: str,
        handler: BoundHandler,
        binders: dict[str, DependencyBinder],
    ) -> None:
        if action not in self.gate.policy.allowed_actions:
            raise ValueError(f"cannot register action absent from policy: {action!r}")
        if action in self._handlers or action in self._bound_handlers:
            raise ValueError(f"action already registered: {action!r}")
        dependencies = self.gate.policy.action_dependencies.get(action, {})
        if not dependencies:
            raise ValueError(f"action has no execution-binding policy: {action!r}")
        if set(binders) != set(dependencies):
            raise ValueError("registered binder set does not match dependency policy")
        for name, dependency in dependencies.items():
            if binders[name].kind != dependency.kind:
                raise ValueError(
                    f"binder kind for {name!r} does not match dependency policy"
                )
        self._bound_handlers[action] = (handler, dict(binders))

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
        execution_id = uuid4().hex
        binding: ExecutionBinding | None = None
        binding_id: str | None = None
        if decision.verdict is not Verdict.AUTHORIZED:
            outcome = ExecutionOutcome(
                proposal.id,
                False,
                error=f"Armour decision: {decision.verdict.value}",
                execution_id=execution_id,
            )
        elif (
            proposal.action not in self._handlers
            and proposal.action not in self._bound_handlers
        ):
            outcome = ExecutionOutcome(
                proposal.id,
                False,
                error="authorized action has no registered handler",
                execution_id=execution_id,
            )
        else:
            if proposal.action in self._bound_handlers:
                _bound_handler, binders = self._bound_handlers[proposal.action]
                try:
                    binding = prepare_execution_binding(
                        proposal,
                        self.gate.policy,
                        execution_id=execution_id,
                        binders=binders,
                        monotonic_ns=self._monotonic_ns,
                    )
                    binding_id = binding.id
                except Exception as exc:
                    outcome = ExecutionOutcome(
                        proposal.id,
                        False,
                        error=f"binding failed: {type(exc).__name__}",
                        execution_id=execution_id,
                    )
                    return self._complete(proposal, decision, outcome, execution_id)
            if self.receipts is not None:
                try:
                    self.receipts.append(
                        proposal,
                        decision,
                        phase="started",
                        execution_id=execution_id,
                    )
                except Exception as exc:
                    if binding is not None:
                        binding.close()
                    audit_error = f"audit start failed: {type(exc).__name__}"
                    return ExecutionOutcome(
                        proposal.id,
                        False,
                        error=f"audit start failed; handler not executed: {type(exc).__name__}",
                        execution_id=execution_id,
                        binding_id=binding_id,
                        audit_status=AuditStatus.START_FAILED,
                        audit_error=audit_error,
                    )
            try:
                if binding is None:
                    output = self._handlers[proposal.action](proposal)
                else:
                    handler, _binders = self._bound_handlers[proposal.action]
                    context = binding.consume(
                        proposal=proposal,
                        policy_fingerprint=self.gate.policy.fingerprint(),
                        execution_id=execution_id,
                    )
                    try:
                        output = handler(proposal, context)
                    finally:
                        context.close()
                outcome = ExecutionOutcome(
                    proposal.id,
                    True,
                    output=output,
                    execution_id=execution_id,
                    binding_id=binding_id,
                )
            except BindingExpired as exc:
                outcome = ExecutionOutcome(
                    proposal.id,
                    False,
                    error=f"binding expired: {exc}",
                    execution_id=execution_id,
                    binding_id=binding_id,
                )
            except BindingError as exc:
                outcome = ExecutionOutcome(
                    proposal.id,
                    False,
                    error=f"binding failed: {type(exc).__name__}",
                    execution_id=execution_id,
                    binding_id=binding_id,
                )
            except Exception as exc:
                outcome = ExecutionOutcome(
                    proposal.id,
                    False,
                    error=f"{type(exc).__name__}: {exc}",
                    execution_id=execution_id,
                    binding_id=binding_id,
                )
            finally:
                if binding is not None:
                    binding.close()
        return self._complete(proposal, decision, outcome, execution_id)

    def _complete(
        self,
        proposal: ActionProposal,
        decision: Any,
        outcome: ExecutionOutcome,
        execution_id: str,
    ) -> ExecutionOutcome:
        if self.receipts is not None:
            completed = replace(outcome, audit_status=AuditStatus.COMPLETED)
            try:
                self.receipts.append(
                    proposal,
                    decision,
                    completed,
                    phase="completed",
                    execution_id=execution_id,
                )
            except Exception as exc:
                return replace(
                    outcome,
                    audit_status=AuditStatus.COMPLETION_FAILED,
                    audit_error=f"audit completion failed: {type(exc).__name__}",
                )
            return completed
        return outcome
