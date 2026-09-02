"""Armour: a deterministic safety boundary for autonomous agents."""

from .approvals import ApprovalVerifier, HMACApprovalVerifier
from .audit import ReceiptIntegrityError, ReceiptLog, ReceiptVerification
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
from .ledger import (
    ApprovalClaim,
    ApprovalLedger,
    ApprovalLedgerError,
    InMemoryApprovalLedger,
    SQLiteApprovalLedger,
)
from .models import ActionProposal, Decision, Effect, ExecutionOutcome, HumanApproval, Risk, Verdict
from .policy import Policy
from .schemas import ActionSchema

__all__ = [
    "ActionProposal",
    "ActionSchema",
    "ApprovalVerifier",
    "ApprovalClaim",
    "ApprovalLedger",
    "ApprovalLedgerError",
    "ArmourGate",
    "Decision",
    "Effect",
    "ExecutionOutcome",
    "GuardedExecutor",
    "HumanApproval",
    "HMACApprovalVerifier",
    "InMemoryApprovalLedger",
    "Mutation",
    "MutationOutcome",
    "MutationReport",
    "MutationRunner",
    "Policy",
    "ReceiptLog",
    "ReceiptIntegrityError",
    "ReceiptVerification",
    "Risk",
    "SQLiteApprovalLedger",
    "STANDARD_INVARIANTS",
    "Verdict",
    "standard_mutant_family",
]
