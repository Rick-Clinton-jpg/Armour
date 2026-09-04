"""Atomic single-use approval ledgers owned by the trusted host."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
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
    integrity_protected: bool

    def claim(self, approval: HumanApproval) -> bool:
        """Atomically claim an approval nonce, returning false on replay."""


class InMemoryApprovalLedger:
    """Process-local development ledger.

    This implementation is thread-safe but intentionally not durable or safe
    across multiple processes.
    """

    durable = False
    integrity_protected = False

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


class ApprovalCheckpoint(Protocol):
    """Host-owned monotonic anchor for approval-ledger generations.

    ``advance_generation`` must atomically retain the maximum generation it has
    seen. Receiving an older generation is a successful no-op.
    """

    def read_generation(self, namespace: str) -> int | None: ...

    def advance_generation(self, namespace: str, generation: int) -> None: ...


class SQLiteApprovalLedger:
    """Durable, process-safe approval ledger backed by SQLite.

    Nonce uniqueness is scoped only by deployment namespace. Policy and key
    identifiers are retained as evidence, not used to reset replay protection.
    """

    durable = True
    schema_version = 2

    def __init__(
        self,
        path: str | Path,
        *,
        deployment_namespace: str = "default",
        timeout_seconds: float = 5.0,
        integrity_key: bytes | None = None,
        checkpoint: ApprovalCheckpoint | None = None,
        trust_existing_claims: bool = False,
    ) -> None:
        if not isinstance(deployment_namespace, str) or not deployment_namespace.strip():
            raise ValueError("deployment_namespace must be a non-empty string")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if integrity_key is not None and (
            not isinstance(integrity_key, bytes) or len(integrity_key) < 32
        ):
            raise ValueError("integrity_key must contain at least 32 bytes")
        if checkpoint is not None and integrity_key is None:
            raise ValueError("checkpoint requires an integrity_key")
        self.path = Path(path).expanduser().resolve()
        self.deployment_namespace = deployment_namespace
        self.timeout_seconds = timeout_seconds
        self._integrity_key = integrity_key
        self._checkpoint = checkpoint
        self._trust_existing_claims = bool(trust_existing_claims)
        self.integrity_protected = integrity_key is not None
        self._initialize()
        self._initialize_integrity()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        try:
            connection.execute(
                f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}"
            )
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except Exception:
            connection.close()
            raise

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
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS approval_ledger_integrity (
                        deployment_namespace TEXT PRIMARY KEY,
                        generation INTEGER NOT NULL,
                        content_digest TEXT NOT NULL,
                        authenticator TEXT NOT NULL
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

    def _content_digest(self, connection: sqlite3.Connection) -> str:
        rows = connection.execute(
            """
            SELECT id, deployment_namespace, nonce, proposal_id,
                   proposal_fingerprint, policy_fingerprint, approved_by,
                   key_id, claimed_at
            FROM approval_claims
            WHERE deployment_namespace = ? ORDER BY id
            """,
            (self.deployment_namespace,),
        ).fetchall()
        try:
            canonical = json.dumps(
                rows, separators=(",", ":"), allow_nan=False
            ).encode()
        except (TypeError, ValueError) as exc:
            raise ApprovalLedgerError(
                "approval ledger contains non-canonical data"
            ) from exc
        return hashlib.sha256(canonical).hexdigest()

    def _authenticator(self, generation: int, content_digest: str) -> str:
        assert self._integrity_key is not None
        payload = json.dumps(
            {
                "component": "approval_ledger",
                "deployment_namespace": self.deployment_namespace,
                "generation": generation,
                "content_digest": content_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(self._integrity_key, payload, hashlib.sha256).hexdigest()

    def _read_checkpoint(self) -> int | None:
        if self._checkpoint is None:
            return None
        try:
            generation = self._checkpoint.read_generation(
                self.deployment_namespace
            )
        except Exception as exc:
            raise ApprovalLedgerError("approval checkpoint unavailable") from exc
        if generation is not None and (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
        ):
            raise ApprovalLedgerError("approval checkpoint is invalid")
        return generation

    def _assert_checkpoint_not_ahead(self, generation: int) -> None:
        anchored = self._read_checkpoint()
        if anchored is not None and anchored > generation:
            raise ApprovalLedgerError("approval ledger rollback detected")

    def _advance_checkpoint(self, generation: int) -> None:
        if self._checkpoint is None:
            return
        self._assert_checkpoint_not_ahead(generation)
        try:
            self._checkpoint.advance_generation(
                self.deployment_namespace, generation
            )
        except Exception as exc:
            raise ApprovalLedgerError("approval checkpoint unavailable") from exc

    def _verify_integrity(self, connection: sqlite3.Connection) -> int:
        if self._integrity_key is None:
            return 0
        content_digest = self._content_digest(connection)
        row = connection.execute(
            """
            SELECT generation, content_digest, authenticator
            FROM approval_ledger_integrity
            WHERE deployment_namespace = ?
            """,
            (self.deployment_namespace,),
        ).fetchone()
        if row is None:
            count = connection.execute(
                """
                SELECT COUNT(*) FROM approval_claims
                WHERE deployment_namespace = ?
                """,
                (self.deployment_namespace,),
            ).fetchone()[0]
            if count and not self._trust_existing_claims:
                raise ApprovalLedgerError(
                    "existing approval ledger is unsealed; explicit trust is required"
                )
            generation = 0
            authenticator = self._authenticator(generation, content_digest)
            connection.execute(
                """
                INSERT INTO approval_ledger_integrity (
                    deployment_namespace, generation,
                    content_digest, authenticator
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    self.deployment_namespace, generation,
                    content_digest, authenticator,
                ),
            )
        else:
            generation, stored_digest, stored_authenticator = row
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 0
                or not isinstance(stored_digest, str)
                or not isinstance(stored_authenticator, str)
            ):
                raise ApprovalLedgerError("approval ledger integrity state is invalid")
            expected = self._authenticator(generation, stored_digest)
            if (
                not hmac.compare_digest(stored_digest, content_digest)
                or not hmac.compare_digest(stored_authenticator, expected)
            ):
                raise ApprovalLedgerError("approval ledger integrity check failed")
        self._assert_checkpoint_not_ahead(generation)
        return generation

    def _reseal(self, connection: sqlite3.Connection, generation: int) -> int:
        if self._integrity_key is None:
            return 0
        next_generation = generation + 1
        content_digest = self._content_digest(connection)
        authenticator = self._authenticator(next_generation, content_digest)
        connection.execute(
            """
            UPDATE approval_ledger_integrity
            SET generation = ?, content_digest = ?, authenticator = ?
            WHERE deployment_namespace = ?
            """,
            (
                next_generation, content_digest, authenticator,
                self.deployment_namespace,
            ),
        )
        return next_generation

    def _initialize_integrity(self) -> None:
        if self._integrity_key is None:
            return
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                generation = self._verify_integrity(connection)
                connection.commit()
        except ApprovalLedgerError:
            raise
        except sqlite3.Error as exc:
            raise ApprovalLedgerError("approval ledger integrity unavailable") from exc
        self._advance_checkpoint(generation)
        self._trust_existing_claims = False

    def claim(self, approval: HumanApproval) -> bool:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                generation = self._verify_integrity(connection)
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
                        self._advance_checkpoint(generation)
                        return False
                    raise
                next_generation = self._reseal(connection, generation)
                connection.commit()
                self._advance_checkpoint(next_generation)
                return True
        except ApprovalLedgerError:
            raise
        except sqlite3.Error as exc:
            raise ApprovalLedgerError("approval replay ledger is unavailable") from exc

    def claims(self) -> tuple[ApprovalClaim, ...]:
        """Return durable claim evidence in insertion order."""
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                generation = self._verify_integrity(connection)
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
                self._advance_checkpoint(generation)
                connection.commit()
        except ApprovalLedgerError:
            raise
        except sqlite3.Error as exc:
            raise ApprovalLedgerError("approval replay ledger is unavailable") from exc
        return tuple(ApprovalClaim(*row) for row in rows)
