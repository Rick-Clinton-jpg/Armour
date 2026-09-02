"""Atomic single-use approval ledgers owned by the trusted host."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
from threading import Lock
import time
from typing import Iterator, Protocol

from .models import HumanApproval


class ApprovalLedgerError(RuntimeError):
    """Raised when replay state cannot be checked and durably recorded."""


class ApprovalLedger(Protocol):
    """Atomic replay boundary for human approvals."""

    durable: bool

    def claim(self, approval: HumanApproval) -> bool:
        """Atomically claim an approval nonce, returning false on replay."""


class InMemoryApprovalLedger:
    """Process-local development ledger.

    This implementation is thread-safe but intentionally not durable or safe
    across multiple processes.
    """

    durable = False

    def __init__(self) -> None:
        self._lock = Lock()
        self._nonces: set[str] = set()

    def claim(self, approval: HumanApproval) -> bool:
        with self._lock:
            if approval.nonce in self._nonces:
                return False
            self._nonces.add(approval.nonce)
            return True


@dataclass(frozen=True, slots=True)
class ApprovalClaim:
    deployment_namespace: str
    nonce: str
    proposal_id: str
    proposal_fingerprint: str
    policy_fingerprint: str
    approved_by: str
    key_id: str
    claimed_at: float


class SQLiteApprovalLedger:
    """Durable, process-safe approval ledger backed by SQLite.

    Nonce uniqueness is scoped only by deployment namespace. Policy and key
    identifiers are retained as evidence, not used to reset replay protection.
    """

    durable = True
    schema_version = 1

    def __init__(
        self,
        path: str | Path,
        *,
        deployment_namespace: str = "default",
        timeout_seconds: float = 5.0,
    ) -> None:
        if not isinstance(deployment_namespace, str) or not deployment_namespace.strip():
            raise ValueError("deployment_namespace must be a non-empty string")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path).expanduser().resolve()
        self.deployment_namespace = deployment_namespace
        self.timeout_seconds = timeout_seconds
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection and always release its file descriptor.

        ``sqlite3.Connection``'s own context manager commits or rolls back but
        does not close the connection, so using it directly leaks resources
        under repeated claims.
        """
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR,
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            os.chmod(self.path, 0o600)
            with self._connection() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS armour_schema (
                        component TEXT PRIMARY KEY,
                        version INTEGER NOT NULL
                    )
                    """
                )
                row = connection.execute(
                    "SELECT version FROM armour_schema WHERE component = ?",
                    ("approval_ledger",),
                ).fetchone()
                if row is not None and row[0] > self.schema_version:
                    raise ApprovalLedgerError(
                        "approval ledger schema is newer than this Armour version"
                    )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS approval_claims (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        deployment_namespace TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        proposal_id TEXT NOT NULL,
                        proposal_fingerprint TEXT NOT NULL,
                        policy_fingerprint TEXT NOT NULL,
                        approved_by TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        claimed_at REAL NOT NULL,
                        UNIQUE (deployment_namespace, nonce)
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO armour_schema(component, version)
                    VALUES (?, ?)
                    ON CONFLICT(component) DO UPDATE SET version = excluded.version
                    """,
                    ("approval_ledger", self.schema_version),
                )
                connection.commit()
        except ApprovalLedgerError:
            raise
        except sqlite3.Error as exc:
            raise ApprovalLedgerError("approval ledger initialization failed") from exc
        except OSError as exc:
            raise ApprovalLedgerError("approval ledger path is unavailable") from exc

    def claim(self, approval: HumanApproval) -> bool:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        """
                        INSERT INTO approval_claims (
                            deployment_namespace,
                            nonce,
                            proposal_id,
                            proposal_fingerprint,
                            policy_fingerprint,
                            approved_by,
                            key_id,
                            claimed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self.deployment_namespace,
                            approval.nonce,
                            approval.proposal_id,
                            approval.proposal_fingerprint,
                            approval.policy_fingerprint,
                            approval.approved_by,
                            approval.key_id,
                            time.time(),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    connection.rollback()
                    if getattr(exc, "sqlite_errorcode", None) in {
                        sqlite3.SQLITE_CONSTRAINT_UNIQUE,
                        sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
                    }:
                        return False
                    raise
                connection.commit()
                return True
        except sqlite3.Error as exc:
            raise ApprovalLedgerError("approval replay ledger is unavailable") from exc

    def claims(self) -> tuple[ApprovalClaim, ...]:
        """Return durable claim evidence in insertion order."""
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    """
                    SELECT deployment_namespace, nonce, proposal_id,
                           proposal_fingerprint, policy_fingerprint,
                           approved_by, key_id, claimed_at
                    FROM approval_claims
                    WHERE deployment_namespace = ?
                    ORDER BY id
                    """,
                    (self.deployment_namespace,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise ApprovalLedgerError("approval replay ledger is unavailable") from exc
        return tuple(ApprovalClaim(*row) for row in rows)
