"""Armour: a deterministic safety boundary for autonomous agents."""

from .approvals import (
    ApprovalVerifier,
    Ed25519ApprovalSigner,
    Ed25519ApprovalVerifier,
    HMACApprovalVerifier,
)
from .audit import ReceiptIntegrityError, ReceiptLog, ReceiptVerification
from .binding import (
    BindingConsumed,
    BindingError,
    BindingExpired,
    BindingMismatch,
    DependencyPolicy,
    ExecutionBinding,
    ExecutionContext,
    prepare_execution_binding,
)
from .executor import GuardedExecutor
from .filesystem_binding import BoundFile, FilesystemBinder
from .memory_sandbox import RememberingGate, SecurityMemorySandbox
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
from .models import (
    ActionProposal,
    AuditStatus,
    Decision,
    Effect,
    ExecutionOutcome,
    HumanApproval,
    Risk,
    Verdict,
)
from .policy import Policy
from .safe_filesystem import UnsafePathError, open_beneath, read_text_beneath
from .schemas import ActionSchema
from .security_memory import (
    IncidentRecord,
    RememberedMutant,
    RememberedMutantOutcome,
    RememberedMutantReport,
    SecurityMemoryError,
    SQLiteIncidentMemory,
    SQLiteMutantMemory,
)

__all__ = [
    "ActionProposal",
    "ActionSchema",
    "ApprovalVerifier",
    "ApprovalClaim",
    "ApprovalLedger",
    "ApprovalLedgerError",
    "ArmourGate",
    "AuditStatus",
    "BindingConsumed",
    "BindingError",
    "BindingExpired",
    "BindingMismatch",
    "BoundFile",
    "Decision",
    "Ed25519ApprovalSigner",
    "Ed25519ApprovalVerifier",
    "Effect",
    "DependencyPolicy",
    "ExecutionBinding",
    "ExecutionContext",
    "ExecutionOutcome",
    "GuardedExecutor",
    "FilesystemBinder",
    "HumanApproval",
    "HMACApprovalVerifier",
    "InMemoryApprovalLedger",
    "IncidentRecord",
    "Mutation",
    "MutationOutcome",
    "MutationReport",
    "MutationRunner",
    "Policy",
    "ReceiptLog",
    "ReceiptIntegrityError",
    "ReceiptVerification",
    "RememberedMutant",
    "RememberedMutantOutcome",
    "RememberedMutantReport",
    "RememberingGate",
    "Risk",
    "SQLiteApprovalLedger",
    "SQLiteIncidentMemory",
    "SQLiteMutantMemory",
    "SecurityMemoryError",
    "SecurityMemorySandbox",
    "STANDARD_INVARIANTS",
    "UnsafePathError",
    "Verdict",
    "open_beneath",
    "prepare_execution_binding",
    "read_text_beneath",
    "standard_mutant_family",
]
