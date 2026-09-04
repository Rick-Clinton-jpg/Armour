# Armour threat model

## Security objective

An untrusted model may propose actions and arguments. It must not be able to make an unregistered, out-of-scope, forbidden, or insufficiently approved side effect cross into a trusted handler merely by changing its output.

## Trusted computing base

- the host application and process
- `Policy` construction and storage
- Armour's mandatory verifier chain and gate
- registered handler implementations
- the human-approval issuance channel
- the configured approval replay ledger and its storage
- any credential, filesystem, network, and audit services used by handlers

The model, prompts, retrieved content, memory, proposal fields, and model-declared risk/effect are untrusted.

Policy construction fails if any allowed action lacks a human-owned effect classification.

## Defended cases

- invented or unregistered action names
- model-declared risk below request or verifier risk
- model-declared effect below the policy-owned effect for an action
- irreversible effects forbidden by policy
- absolute paths resolving outside explicit roots
- relative paths at the trust boundary
- unknown, missing, or nested payload fields for actions with a strict `ActionSchema`
- non-GET/HEAD requests by default
- literal and DNS-resolved non-public network destinations
- selected dangerous command signatures
- approval use against changed proposal arguments
- approval use against a changed policy
- expired, mismatched, or replayed approvals, including after restart and across processes sharing a SQLite ledger
- unsigned approvals and approvals signed by unknown HMAC or Ed25519 keys
- separated Ed25519 verification in which the evaluator holds no approval-signing secret
- receipt modification detectable through a hash chain
- an execution-started receipt written before an authorized handler runs
- completion-receipt failure reported separately from handler success, without
  discarding a successful handler result
- for policy-bound filesystem reads, path replacement after preparation cannot
  redirect the already-open descriptor supplied to the registered handler
- when the optional remembering gate is used, repeated rejections can only
  tighten policy by quarantining the same host-authenticated subject

## Explicit non-goals and residual risks

- Armour is not an operating-system, container, process, or bytecode sandbox.
- Registered handlers are trusted and can violate policy if incorrectly written.
- Ordinary path-based handlers can still reopen a changed path. On supported
  POSIX platforms, filesystem execution binding can instead supply a live,
  no-follow descriptor for the verified resource identity. That guarantee
  holds only when the registered handler uses the supplied capability; it does
  not freeze same-inode contents or authorization. Other filesystem operations
  require equivalent host implementations.
- Execution binding is currently process-local and filesystem-read-only. It has
  no network, DNS, API, database, credential, or cross-process binder.
- Security memory depends on a trustworthy subject identity. An agent allowed
  to choose that identity can evade quarantine or frame another subject.
- Incident memory is behavioral evidence, not truth. Permanent mutant cases
  require explicit trusted-reviewer promotion to limit memory poisoning.
- Security-memory records are authenticated with a host-held key; direct row
  edits, insertions, and deletions fail closed. Detecting replacement by an
  older valid database additionally requires a host-provided monotonic
  checkpoint outside SQLite's rollback boundary. Key secrecy, identity,
  checkpoint durability, and disk exhaustion remain host responsibilities.
- A hostname can resolve differently between verification and connection; network handlers must pin or re-verify the actual connected address.
- Development mode falls back to a process-local approval ledger. Production mode requires durable replay storage.
- `SQLiteApprovalLedger` coordinates processes sharing one database file; separate hosts require a host-provided atomic `ApprovalLedger` implementation.
- An attacker able to replace or roll back the replay database can undermine nonce history; protect the ledger as security state.
- The reference HMAC verifier shares signing authority with the evaluator. Use `Ed25519ApprovalVerifier` when approval issuance must remain isolated from that process.
- Ed25519 key distribution, storage, rotation timing, and real-world reviewer identity remain the host's responsibility.
- Pattern scanning cannot establish semantic safety and is only defense in depth.
- Armour does not protect information already sent to a cloud model.
- It authenticates configured approval keys, not the real-world identity behind them; it does not sign policies, manage credentials, or enforce resource quotas yet.
- Hash chaining exposes tampering but does not prevent deletion of the entire receipt file; external anchoring is required for stronger audit guarantees.
- Process failure during an external side effect can still leave its outcome
  uncertain. Handlers or downstream services must honour an idempotency key for
  safe retry; Armour's staged receipts alone cannot provide exactly-once effects.

## Evaluation rule

Runtime tests prove expected cases. Mutation tests challenge the boundary with named adversarial variants and measure both mutation score and invariant coverage. Neither is a mathematical proof of safety; unmodeled failure families remain possible and should be added when discovered.
