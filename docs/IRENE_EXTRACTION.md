# Irene → Armour extraction

Armour preserves the part of Irene that should remain independent of any agent's cognition.

## Retained as design principles

| Irene concept | Armour form |
|---|---|
| Candidate actions | `ActionProposal` as validated, untrusted data |
| Safety, scope, and network verifiers | Mandatory deterministic verifier chain |
| Risk-based quorum routing | Maximum-risk aggregation and three explicit verdicts |
| Human gate | Proposal-bound `HumanApproval` supplied through a trusted channel |
| Executors | Host-owned registered handlers behind `GuardedExecutor` |
| Decision receipts | Append-only, hash-chained `ReceiptLog` |
| Reversible and least-privilege bias | Effect floors, explicit roots, read-only network default |
| SDCE mutant families and coverage | Offline `MutationRunner`; no candidate execution |

## Corrected during extraction

- Candidate risk is included in the decision. Irene used the parsed request risk for every candidate.
- Core verifiers cannot be replaced accidentally by a caller; only additional checks may be added.
- Network policy checks resolved addresses, not just literal hostnames.
- Relative filesystem paths are rejected at the trust boundary.
- Human approval is tied to one proposal ID instead of represented by a loose boolean.
- Raw model output has an explicit validation entry point.
- Generated code is never loaded as an Armour executor.
- Action effects are policy-owned, preventing a model from understating a registered action.
- Approvals bind to exact proposal and policy fingerprints, expire, and are single-use within a gate process.
- SDCE's mutation and invariant-coverage ideas are retained without importing its in-process sandbox or placeholder consensus/oracle behavior.

## Deliberately excluded

- LLM clients and prompts
- personality and constitution
- memory and retrieval
- goals and planning
- autonomous/continuous loops
- web UI
- research, image, dream, and self-edit executors
- generic shell or arbitrary-code execution

Armour should remain boring. It decides whether a proposed side effect may cross into reality; it does not decide what an agent should want or think about next.
