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
- receipt modification that does not also recompute the affected hash-chain
  suffix is detectable
- when optional receipt checkpoints are enabled and retained separately,
  deletion, truncation, or replacement of the primary receipt chain is
  detectable relative to the surviving checkpoint file
- an execution-started receipt written before an authorized handler runs
- completion-receipt failure reported separately from handler success, without
  discarding a successful handler result
- for policy-bound filesystem reads, path replacement after preparation cannot
  redirect the already-open descriptor supplied to the registered handler
- for policy-bound HTTP(S) GET/HEAD actions, every DNS result must be public
  and the supplied single-use capability sends the fixed request over a socket
  already connected to one verified numeric destination; later DNS changes
  cannot redirect that request and redirects are not followed
- when the optional remembering gate is used, repeated rejections can only
  tighten policy by quarantining the same host-authenticated subject

## Explicit non-goals and residual risks

- Armour is not an operating-system, container, process, or bytecode sandbox.
- Registered handlers are trusted and can violate policy if incorrectly written.
- Ordinary path-based handlers can still reopen a changed path. On supported
  POSIX platforms, filesystem execution binding can instead supply a live,
  no-follow descriptor for the verified resource identity. That guarantee
  holds only when the registered handler uses the supplied capability; it does
  not freeze same-inode contents or authorization and does not prevent access
  through hard-link aliases. Other filesystem operations require equivalent
  host implementations.
- Execution binding is process-local and supports read-only filesystem access
  plus fixed HTTP(S) GET/HEAD requests. It has no general API, database,
  credential, state-changing network, or cross-process binder.
- Security memory depends on a trustworthy subject identity. An agent allowed
  to choose that identity can evade quarantine or frame another subject.
- Incident memory is behavioral evidence, not truth. Permanent mutant cases
  require explicit trusted-reviewer promotion to limit memory poisoning.
- Security-memory records are authenticated with a host-held key; direct row
  edits, insertions, and deletions fail closed. Detecting replacement by an
  older valid database additionally requires a host-provided monotonic
  checkpoint outside SQLite's rollback boundary. Key secrecy, identity,
  checkpoint durability, and disk exhaustion remain host responsibilities.
- The network-binding guarantee holds only when a registered handler uses the
  supplied connection capability. An ordinary or malicious trusted handler can
  still resolve a hostname or open another socket itself. A public destination
  may proxy elsewhere or return hostile content, and binding a peer does not
  freeze remote content or authorization. Custom headers, bodies, automatic
  redirects, and state-changing HTTP methods are outside this binder. The
  maximum-age check prevents a stale request from starting but does not cancel
  an in-flight request; the socket timeout remains a separate host setting.
  The default SSL context verifies HTTPS certificates and hostnames, but Armour
  currently accepts host-supplied contexts that disable those checks. Network
  tests use controlled connections; a live end-to-end HTTPS integration test is
  not present yet.
- Development mode falls back to a process-local approval ledger. Production mode requires durable replay storage.
- Production construction fails immediately when the approval verifier is
  absent, the ledger is not durable, signing authority is not declared isolated
  from the evaluator, or ledger integrity protection is not active. The
  reference production pairing is Ed25519 verification with a keyed durable
  ledger; equivalent host implementations must uphold the same contract.
- `SQLiteApprovalLedger` coordinates processes sharing one database file and
  authenticates production claim state with a host-held key. Separate hosts
  require a host-provided atomic `ApprovalLedger` implementation.
- Direct replay-ledger edits fail closed while its integrity key remains secret.
  Detecting rollback to an older valid ledger additionally requires a monotonic
  `ApprovalCheckpoint` outside SQLite's rollback boundary.
- The reference HMAC verifier shares signing authority with the evaluator and
  is rejected by production construction. Use `Ed25519ApprovalVerifier` or an
  equivalent verifier with isolated signing authority.
- Ed25519 key distribution, storage, rotation timing, and real-world reviewer identity remain the host's responsibility.
- Approval-ledger integrity-key rotation is not implemented. Sealing a legacy
  ledger requires an explicit one-time trust decision and cannot establish that
  the old contents were clean before sealing.
- Pattern scanning cannot establish semantic safety and is only defense in depth.
- Armour does not protect information already sent to a cloud model.
- It authenticates configured approval keys, not the real-world identity behind them; it does not sign policies, manage credentials, or enforce resource quotas yet.
- Hash chaining alone detects accidental or unrechained record modification;
  it does not authenticate the log against an attacker able to rewrite and
  recompute the complete chain, nor does it expose deletion of the entire
  receipt file. The optional local checkpoint file detects primary-log
  deletion or truncation only while that checkpoint survives unchanged. It is
  a second append-only local record, not distributed consensus, trusted
  timestamping, or strong external notarization. An attacker able to delete or
  consistently rewrite both files can still erase the evidence; deployments
  needing stronger guarantees must export checkpoints to independently
  controlled storage.
- Receipt and checkpoint locks coordinate threads within one `ReceiptLog`
  instance only; they do not coordinate multiple processes writing the same
  files.
- The primary receipt is flushed before its checkpoint. A crash between those
  writes leaves the primary ahead of the checkpoint. Verification detects the
  mismatch and later appends fail closed, but recovery is an operator task.
- Process failure during an external side effect can still leave its outcome
  uncertain. Handlers or downstream services must honour an idempotency key for
  safe retry; Armour's staged receipts alone cannot provide exactly-once effects.

## Evaluation rule

Runtime tests prove expected cases. Mutation tests challenge the boundary with named adversarial variants and measure both mutation score and invariant coverage. Neither is a mathematical proof of safety; unmodeled failure families remain possible and should be added when discovered.
