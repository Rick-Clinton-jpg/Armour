# Security memory sandbox

Status: experimental, offline policy-evaluation feature.

This sandbox tests two deliberately separate memories. It is not an operating-
system, container, or process sandbox and it never executes registered handlers.

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
- Database rollback, deletion, or disk exhaustion requires host protection.
- Remembered mutants preserve proposals, not complete external-world state.
- The sandbox does not repair execution-binding limitations such as mutable
  same-inode contents, hard-link aliases, or trusted handlers that ignore a
  supplied capability.
