"""Durable, data-only security memories for Armour.

Incident memory remembers rejected behavior. Mutant memory stores explicitly
promoted proposals as regression cases; it never stores or executes code.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Callable, Iterator, Protocol

from .gate import ArmourGate
from .models import ActionProposal, Decision, Effect, Risk, Verdict


class SecurityMemoryError(RuntimeError):
    """Durable security memory could not be read or updated safely."""


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    id: int
    deployment_namespace: str
    subject_id: str
    proposal_fingerprint: str
    policy_fingerprint: str
    action: str
    families: tuple[str, ...]
    recorded_at: float


class IncidentMemory(Protocol):
    durable: bool

    def record_rejection(
        self, subject_id: str, proposal: ActionProposal, decision: Decision
    ) -> IncidentRecord: ...

    def rejection_count(self, subject_id: str, *, since: float) -> int: ...

    def incidents(self, subject_id: str | None = None) -> tuple[IncidentRecord, ...]: ...


@dataclass(frozen=True, slots=True)
class RememberedMutant:
    id: int
    deployment_namespace: str
    name: str
    proposal: ActionProposal
    expected_verdicts: frozenset[Verdict]
    policy_fingerprint: str
    promoted_by: str
    source_incident_id: int | None
    created_at: float


@dataclass(frozen=True, slots=True)
class RememberedMutantOutcome:
    name: str
    verdict: Verdict
    passed: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RememberedMutantReport:
    outcomes: tuple[RememberedMutantOutcome, ...]

    @property
    def passed(self) -> bool:
        return bool(self.outcomes) and all(outcome.passed for outcome in self.outcomes)

    @property
    def survivors(self) -> tuple[RememberedMutantOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.passed)


class _SQLiteMemory:
    durable = True
    schema_version = 1

    def __init__(
        self,
        path: str | Path,
        *,
        deployment_namespace: str = "default",
        timeout_seconds: float = 5.0,
        wall_clock: Callable[[], float] = time.time,
    ):
        if not isinstance(deployment_namespace, str) or not deployment_namespace.strip():
            raise ValueError("deployment_namespace must be a non-empty string")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path).expanduser().resolve()
        self.deployment_namespace = deployment_namespace
        self.timeout_seconds = timeout_seconds
        self._wall_clock = wall_clock
        self._prepare_file()

    def _prepare_file(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise SecurityMemoryError("security memory path is unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=self.timeout_seconds, isolation_level=None
        )
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize_component(self, component: str, table_sql: str) -> None:
        try:
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
                    "SELECT version FROM armour_schema WHERE component = ?", (component,)
                ).fetchone()
                if row is not None and row[0] > self.schema_version:
                    raise SecurityMemoryError(
                        f"{component} schema is newer than this Armour version"
                    )
                connection.execute(table_sql)
                connection.execute(
                    """
                    INSERT INTO armour_schema(component, version) VALUES (?, ?)
                    ON CONFLICT(component) DO UPDATE SET version = excluded.version
                    """,
                    (component, self.schema_version),
                )
                connection.commit()
        except SecurityMemoryError:
            raise
        except sqlite3.Error as exc:
            raise SecurityMemoryError("security memory initialization failed") from exc


class SQLiteIncidentMemory(_SQLiteMemory):
    """Durable rejected-behavior history scoped by trusted subject identity."""

    def __init__(self, path: str | Path, **kwargs: object):
        super().__init__(path, **kwargs)
        self._initialize_component(
            "incident_memory",
            """
            CREATE TABLE IF NOT EXISTS security_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                deployment_namespace TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                proposal_fingerprint TEXT NOT NULL,
                policy_fingerprint TEXT NOT NULL,
                action TEXT NOT NULL,
                families_json TEXT NOT NULL,
                recorded_at REAL NOT NULL
            )
            """,
        )

    @staticmethod
    def _validate_subject(subject_id: str) -> str:
        if not isinstance(subject_id, str) or not subject_id.strip():
            raise ValueError("subject_id must come from a non-empty trusted identity")
        if len(subject_id) > 256:
            raise ValueError("subject_id is too long")
        return subject_id

    def record_rejection(
        self, subject_id: str, proposal: ActionProposal, decision: Decision
    ) -> IncidentRecord:
        subject_id = self._validate_subject(subject_id)
        if decision.verdict is not Verdict.REJECTED:
            raise ValueError("incident memory records rejected decisions only")
        families = tuple(sorted({check.verifier for check in decision.checks if not check.passed}))
        if not families:
            families = ("unclassified_rejection",)
        recorded_at = self._wall_clock()
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO security_incidents (
                        deployment_namespace, subject_id, proposal_fingerprint,
                        policy_fingerprint, action, families_json, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.deployment_namespace,
                        subject_id,
                        proposal.fingerprint(),
                        decision.policy_fingerprint,
                        proposal.action,
                        json.dumps(families, separators=(",", ":")),
                        recorded_at,
                    ),
                )
                connection.commit()
                incident_id = int(cursor.lastrowid)
        except sqlite3.Error as exc:
            raise SecurityMemoryError("incident memory is unavailable") from exc
        return IncidentRecord(
            incident_id, self.deployment_namespace, subject_id,
            proposal.fingerprint(), decision.policy_fingerprint,
            proposal.action, families, recorded_at,
        )

    def rejection_count(self, subject_id: str, *, since: float) -> int:
        subject_id = self._validate_subject(subject_id)
        try:
            with self._connection() as connection:
                row = connection.execute(
                    """
                    SELECT COUNT(*) FROM security_incidents
                    WHERE deployment_namespace = ? AND subject_id = ? AND recorded_at >= ?
                    """,
                    (self.deployment_namespace, subject_id, since),
                ).fetchone()
        except sqlite3.Error as exc:
            raise SecurityMemoryError("incident memory is unavailable") from exc
        return int(row[0])

    def incidents(self, subject_id: str | None = None) -> tuple[IncidentRecord, ...]:
        parameters: tuple[object, ...] = (self.deployment_namespace,)
        where = "deployment_namespace = ?"
        if subject_id is not None:
            where += " AND subject_id = ?"
            parameters += (self._validate_subject(subject_id),)
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    f"""SELECT id, deployment_namespace, subject_id,
                               proposal_fingerprint, policy_fingerprint, action,
                               families_json, recorded_at
                        FROM security_incidents WHERE {where} ORDER BY id""",
                    parameters,
                ).fetchall()
        except sqlite3.Error as exc:
            raise SecurityMemoryError("incident memory is unavailable") from exc
        return tuple(
            IncidentRecord(
                row[0], row[1], row[2], row[3], row[4], row[5],
                tuple(json.loads(row[6])), row[7],
            )
            for row in rows
        )


class SQLiteMutantMemory(_SQLiteMemory):
    """Human-promoted, data-only regression proposals."""

    def __init__(self, path: str | Path, **kwargs: object):
        super().__init__(path, **kwargs)
        self._initialize_component(
            "mutant_memory",
            """
            CREATE TABLE IF NOT EXISTS remembered_mutants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                deployment_namespace TEXT NOT NULL,
                name TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                expected_verdicts_json TEXT NOT NULL,
                policy_fingerprint TEXT NOT NULL,
                promoted_by TEXT NOT NULL,
                source_incident_id INTEGER,
                created_at REAL NOT NULL,
                UNIQUE (deployment_namespace, name)
            )
            """,
        )

    def remember(
        self,
        name: str,
        proposal: ActionProposal,
        *,
        expected_verdicts: frozenset[Verdict],
        policy_fingerprint: str,
        promoted_by: str,
        source_incident_id: int | None = None,
    ) -> RememberedMutant:
        if not isinstance(name, str) or not name.strip() or len(name) > 256:
            raise ValueError("mutant name must be non-empty and at most 256 characters")
        if not isinstance(promoted_by, str) or not promoted_by.strip():
            raise ValueError("promoted_by must identify the trusted reviewer")
        expected_verdicts = frozenset(expected_verdicts)
        if not expected_verdicts or any(not isinstance(item, Verdict) for item in expected_verdicts):
            raise ValueError("expected_verdicts must contain Armour verdicts")
        if not isinstance(policy_fingerprint, str) or not policy_fingerprint:
            raise ValueError("policy_fingerprint must be a non-empty string")
        if source_incident_id is not None and (
            not isinstance(source_incident_id, int)
            or isinstance(source_incident_id, bool)
            or source_incident_id < 1
        ):
            raise ValueError("source_incident_id must be a positive integer")
        proposal_json = json.dumps(
            {
                "id": proposal.id,
                "action": proposal.action,
                "effect": proposal.effect.value,
                "risk": proposal.risk.name.lower(),
                "resource": proposal.resource,
                "method": proposal.method,
                "payload": proposal.payload_data(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        verdicts_json = json.dumps(sorted(item.value for item in expected_verdicts))
        created_at = self._wall_clock()
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO remembered_mutants (
                        deployment_namespace, name, proposal_json,
                        expected_verdicts_json, policy_fingerprint, promoted_by,
                        source_incident_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.deployment_namespace, name, proposal_json, verdicts_json,
                        policy_fingerprint, promoted_by, source_incident_id, created_at,
                    ),
                )
                connection.commit()
                mutant_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"remembered mutant already exists: {name!r}") from exc
        except sqlite3.Error as exc:
            raise SecurityMemoryError("mutant memory is unavailable") from exc
        return RememberedMutant(
            mutant_id, self.deployment_namespace, name, proposal,
            expected_verdicts, policy_fingerprint, promoted_by,
            source_incident_id, created_at,
        )

    def mutants(self) -> tuple[RememberedMutant, ...]:
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    """
                    SELECT id, deployment_namespace, name, proposal_json,
                           expected_verdicts_json, policy_fingerprint, promoted_by,
                           source_incident_id, created_at
                    FROM remembered_mutants
                    WHERE deployment_namespace = ? ORDER BY id
                    """,
                    (self.deployment_namespace,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise SecurityMemoryError("mutant memory is unavailable") from exc
        remembered = []
        for row in rows:
            raw = json.loads(row[3])
            proposal = ActionProposal(
                action=raw["action"], effect=Effect(raw["effect"]),
                risk=Risk[raw["risk"].upper()], resource=raw["resource"],
                method=raw["method"], payload=raw["payload"], id=raw["id"],
            )
            remembered.append(
                RememberedMutant(
                    row[0], row[1], row[2], proposal,
                    frozenset(Verdict(item) for item in json.loads(row[4])),
                    row[5], row[6], row[7], row[8],
                )
            )
        return tuple(remembered)

    def run(self, gate: ArmourGate) -> RememberedMutantReport:
        outcomes = []
        for mutant in self.mutants():
            decision = gate.evaluate(mutant.proposal)
            outcomes.append(
                RememberedMutantOutcome(
                    mutant.name,
                    decision.verdict,
                    decision.verdict in mutant.expected_verdicts,
                    decision.reasons,
                )
            )
        return RememberedMutantReport(tuple(outcomes))
