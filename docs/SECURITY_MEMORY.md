# Security memory sandbox

Status: experimental, offline policy-evaluation feature.

This sandbox tests two deliberately separate memories. It is not an operating-
system, container, or process sandbox and it never executes registered handlers.

## Integrity protection

The remembering gate and combined sandbox require a host-supplied
`integrity_key` of at least 32 bytes. Armour authenticates the complete current
contents and generation of each memory namespace with HMAC-SHA-256 before it
uses the records. Inserting, editing, or deleting a row directly in SQLite—or
opening the database with the wrong key—therefore fails closed with
`SecurityMemoryError`.

```python
incident_memory = SQLiteIncidentMemory(
    "armour-memory.sqlite3",
    integrity_key=load_32_byte_key_from_secret_manager(),
)
mutant_memory = SQLiteMutantMemory(
    "armour-memory.sqlite3",
    integrity_key=load_32_byte_key_from_secret_manager(),
)
```

The key must remain outside the database and remain stable across restarts.
Armour does not store, derive, rotate, or recover this key.

A valid older database contains a valid older authenticator, so a key alone
cannot reveal that the entire file was rolled back. For rollback detection, the
host can also supply a `MemoryCheckpoint` whose generation is stored in a
separate monotonic trust boundary. If its generation is ahead of SQLite, Armour
fails closed. The checkpoint implementation must atomically retain the maximum
generation it receives; another ordinary file beside the database is not an
independent rollback boundary.

Existing unsealed records are not authenticated automatically. The first
keyed opening fails unless the operator explicitly sets
`trust_existing_records=True` after independently validating the old database.
That one-time action seals the current contents; it cannot prove they were
untampered before sealing.

## Incident memory

`SQLiteIncidentMemory` durably records rejected proposals under a host-supplied
subject identity. Attack families come from Armour's failed verifier names, not
from fields supplied by the agent. `RememberingGate` may use recent rejection
counts to quarantine that subject. Memory can therefore tighten a decision but
can never authorize something the underlying `ArmourGate` rejected.

The host must authenticate `subject_id`; letting an agent choose it permits
identity rotation or framing. The time window allows old incidents to stop
causing an active quarantine while retaining their forensic record.
Per-subject and per-deployment ceilings bound storage growth. Old entries for a
single subject rotate while preserving enough recent entries for quarantine.
If the deployment-wide ceiling would be exceeded, the write fails instead of
evicting another subject's security history.

## Mutant memory

`SQLiteMutantMemory` stores data-only `ActionProposal` snapshots. It never stores
Python callbacks or automatically converts traffic into executable tests. A
trusted reviewer must explicitly promote a proposal that incident memory has
already observed as rejected. Replaying the remembered mutants against a new
policy exposes any case that becomes authorized.
Exact proposal fingerprints are unique and a configurable capacity stops alias
names or endless reviewed variants from growing the store without limit.
Opening the initial schema upgrades it in place and retains the earliest record
when that older database already contains exact proposal aliases.

## Why they remain separate

Runtime evidence is noisy and potentially attacker-controlled. Permanent
regression expectations are trusted engineering decisions. Automatically
turning the former into the latter would let attackers poison Armour's future
judgment. Promotion therefore records the reviewer and source incident.

## Current limits

- Quarantine is based on rejected-proposal count, not behavioral similarity.
- The count check and incident write are separate transactions; quarantine is
  eventually consistent across concurrent processes, not a global atomic lock.
- Identity authentication belongs to the host integration.
- SQLite coordinates processes on one host, not a distributed fleet.
- Row insertion, editing, and deletion are detected only while the integrity
  key remains secret. Full-file rollback/deletion requires a trustworthy
  external `MemoryCheckpoint` to distinguish old valid state from fresh state.
- Integrity verification hashes the namespace contents and is currently O(n)
  per memory operation; the configured capacity bounds that work.
- Integrity-key rotation and recovery are not implemented yet.
- Disk exhaustion still requires host monitoring and capacity planning.
- Remembered mutants preserve proposals, not complete external-world state.
- The sandbox does not repair execution-binding limitations such as mutable
  same-inode contents, hard-link aliases, or trusted handlers that ignore a
  supplied capability.
