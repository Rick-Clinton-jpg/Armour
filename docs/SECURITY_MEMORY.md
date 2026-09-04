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

## Mutant memory

`SQLiteMutantMemory` stores data-only `ActionProposal` snapshots. It never stores
Python callbacks or automatically converts traffic into executable tests. A
trusted reviewer must explicitly promote a proposal that incident memory has
already observed as rejected. Replaying the remembered mutants against a new
policy exposes any case that becomes authorized.

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
