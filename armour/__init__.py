"""Armour: a deterministic safety boundary for autonomous agents."""

from .audit import ReceiptLog
from .executor import GuardedExecutor
from .evaluation import (
    Mutation,
    MutationOutcome,
    MutationReport,
    MutationRunner,
    STANDARD_INVARIANTS,
    standard_mutant_family,
)
from .gate import ArmourGate
from .models import ActionProposal, Decision, Effect, ExecutionOutcome, HumanApproval, Risk, Verdict
from .policy import Policy

__all__ = [
    "ActionProposal",
    "ArmourGate",
    "Decision",
    "Effect",
    "ExecutionOutcome",
    "GuardedExecutor",
    "HumanApproval",
    "Mutation",
    "MutationOutcome",
    "MutationReport",
    "MutationRunner",
    "Policy",
    "ReceiptLog",
    "Risk",
    "STANDARD_INVARIANTS",
    "Verdict",
    "standard_mutant_family",
]
