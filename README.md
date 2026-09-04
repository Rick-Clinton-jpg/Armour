# Armour

Armour is a deterministic safety boundary for AI agents.

> [!WARNING]
> **Armour is an experimental work in progress.** It has not received a
> production security audit and must not be treated as a complete security
> boundary. Evaluate it independently and use it entirely at your own risk.

An agent may plan freely and propose actions. Armour—not the agent—decides whether each action is authorized, rejected, or requires explicit human approval. Armour contains no LLM, autonomy loop, personality, memory system, shell executor, or self-modification mechanism.

## Install

Armour requires Python 3.11+ and has no runtime dependencies.

```bash
git clone https://github.com/Rick-Clinton-jpg/Armour.git
cd Armour
pip install -e .
```

Install the optional cryptographic support for separated Ed25519 approval signing and verification:

```bash
pip install -e '.[crypto]'
```

## Trust boundary

```text
Untrusted agent/model
        │ ActionProposal
        ▼
     ArmourGate
        ├─ action allow-list
        ├─ effect/risk floor
        ├─ filesystem confinement
        ├─ public read-only network policy
        └─ selected dangerous-content signatures (advisory)
        │
        ├─ REJECTED
        ├─ ESCALATED ── explicit human approval
        └─ AUTHORIZED
                │
                ▼
        registered host handler
                │
                ▼
       hash-chained receipt
```

The host application owns policy and executor registration. An agent can supply a proposal, but it cannot add itself to the allow-list or provide executable code as the handler. Action effects are also human-owned policy metadata: a model cannot label a known destructive action as read-only to lower its risk.

## Example

```python
from pathlib import Path

from armour import (
    ActionProposal,
    ArmourGate,
    Effect,
    GuardedExecutor,
    Policy,
    ReceiptLog,
    Risk,
    read_text_beneath,
)

workspace = Path("/srv/agent-workspace")
policy = Policy(
    allowed_actions=frozenset({"read_note", "write_note"}),
    action_effects={
        "read_note": Effect.READ_ONLY,
        "write_note": Effect.STATE_CHANGING,
    },
    allowed_roots=(workspace,),
    policy_id="notes-agent",
    revision=1,
)
executor = GuardedExecutor(
    ArmourGate(policy), ReceiptLog(workspace / "receipts.jsonl")
)
executor.register(
    "read_note",
    lambda proposal: read_text_beneath(
        workspace, Path(proposal.resource).relative_to(workspace)
    ),
)

proposal = ActionProposal(
    action="read_note",
    effect=Effect.READ_ONLY,
    risk=Risk.LOW,
    resource="/srv/agent-workspace/notes/plan.md",
)
outcome = executor.execute(proposal)
```

## Design guarantees

- Unknown actions fail closed.
- Every allowed action requires a policy-owned effect classification; missing metadata is a policy construction error.
- Risk is the maximum of request risk, proposal risk, and verifier-inferred risk. A model cannot lower it.
- Irreversible effects are forbidden by default.
- By default, `human_gate_at=Risk.HIGH`, so high-risk actions require separately
  supplied human approval; the host can configure a different threshold.
- Approvals bind to the proposal ID, exact arguments, policy fingerprint, approving identity, expiry, and a single-use nonce.
- Filesystem paths must be absolute and remain beneath explicit roots after resolution.
- Optional `ActionSchema` contracts reject unknown payload keys and identify the exact filesystem fields shared by verification and the registered handler.
- The default network policy permits GET/HEAD and rejects private, loopback,
  link-local, reserved, and otherwise non-public addresses after DNS resolution.
  These `Policy` settings are host-configurable; the read-only `NetworkBinder`
  remains limited to GET/HEAD and public resolved addresses.
- Execution is limited to host-registered Python callables; proposals cannot contain executable handlers.
- Every decision and outcome can be written to a hash-chained JSONL receipt log.
- Handler success and audit success are reported separately. If a completion
  receipt fails after a handler returns, Armour preserves the successful output
  and reports `audit_status="completion_failed"`; callers must not retry the
  effect solely because its audit record is incomplete.

Armour is a policy boundary, not a complete sandbox. Host handlers remain trusted code and must avoid time-of-check/time-of-use mistakes. Bound read-only handlers can use `FilesystemBinder` for an already-open no-follow file or `NetworkBinder` for one fixed GET/HEAD request over an already-connected verified public peer. These guarantees apply only when the handler uses the supplied capability; other operations still require equivalently safe host implementations.

### Mirror Loop (experimental)

The optional Mirror Loop prototype accepts attempts from an already rejected or
escalated proposal as inert text, reflects that text through a bounded state
machine, and produces hash-only evidence for trusted review. Active terminal
and Unicode controls become visible tokens in a typed, still-untrusted
reflection value. Sessions are bound
to one proposal, policy, and execution ID and terminate on scope mismatch,
expiry, repetition, step, or byte limits. It never executes the reflected text
and does not automatically teach security memory.

Mirror Loop is not a shell sandbox and must not be placed in front of a real
terminal without separate process or virtual-machine isolation, credential
removal, and deny-by-default egress. See [the exact experimental guarantee and
non-goals](docs/MIRROR_LOOP.md).

Execution-binding dependency age has an absolute 60-second freshness ceiling;
host policy may only make it shorter. Mirror Loop similarly has non-negotiable
outer ceilings documented in its design. Armour's evidence labels and the gate
for independent review are defined in
[the verification protocol](docs/VERIFICATION_PROTOCOL.md).

### Filesystem execution binding (experimental)

Actions can require a host-owned filesystem dependency and receive the
already-open file capability that Armour verified:

```python
from armour import DependencyPolicy, FilesystemBinder

bound_policy = Policy(
    allowed_actions=frozenset({"read_note"}),
    action_effects={"read_note": Effect.READ_ONLY},
    allowed_roots=(workspace,),
    action_dependencies={
        "read_note": {
            "resource": DependencyPolicy(kind="filesystem", max_age_ms=50),
        }
    },
)
bound_executor = GuardedExecutor(ArmourGate(bound_policy))
bound_executor.register_bound(
    "read_note",
    lambda _proposal, context: context.capability("resource").read_text(),
    {"resource": FilesystemBinder()},
)
```

The binding is single-use and scoped to one proposal fingerprint, policy
fingerprint, and execution ID. Path substitution after preparation cannot
redirect the open descriptor. This binds resource identity only: deadlines and
state/version checks remain necessary for mutable contents or authorization.
See [the execution-binding design](docs/EXECUTION_BINDING.md) for the exact
guarantee, invariants, and current non-goals. A read-only HTTP(S)
`NetworkBinder` is implemented; general API and state-changing network binders
are not.

### Security memory sandbox (experimental)

Armour can optionally test two forms of durable memory without allowing either
one to rewrite its base policy:

- Incident memory records rejected behavior under a host-authenticated subject
  identity and can quarantine that subject after a configured number of recent
  rejections.
- Mutant memory stores only reviewer-promoted, data-only proposals and replays
  them against later policies to expose regressions.

Both operational wrappers require a host-held integrity key. Direct SQLite row
tampering then fails closed. A host-provided monotonic checkpoint can also
detect replacement with an older valid database; keeping that checkpoint in
the same rollback boundary as SQLite does not add this protection.

This is an offline policy-evaluation sandbox, not process or operating-system
containment. Runtime observations never promote themselves into permanent
tests. See [the security-memory design](docs/SECURITY_MEMORY.md) for its trust
boundary and limitations.

Raw model JSON should enter through `ActionProposal.from_untrusted(...)`. Human approval is represented by a signed `HumanApproval` bound to one exact proposal and policy version. Unsigned approvals are never trusted. The host—not the model—must create approvals through a separate trusted interaction.

For separated deployments, the approval service holds the Ed25519 private key:

```python
from armour import Ed25519ApprovalSigner

approval_signer = Ed25519ApprovalSigner(
    "review-service-2026-01",
    load_secret_from_trusted_store("ARMOUR_ED25519_PRIVATE_KEY"),
)
approval = approval_signer.issue(
    proposal,
    policy_fingerprint=policy.fingerprint(),
    approved_by="rick@example.com",
    ttl_seconds=120,
)
```

The Armour evaluator receives only the corresponding raw public key:

```python
from armour import ArmourGate, Ed25519ApprovalVerifier, SQLiteApprovalLedger

approval_verifier = Ed25519ApprovalVerifier(
    {"review-service-2026-01": load_public_key("armour-review.pub")}
)
approval_ledger = SQLiteApprovalLedger(
    workspace / "armour-approvals.sqlite3",
    deployment_namespace="notes-production",
    integrity_key=load_32_byte_key_from_secret_manager(),
)
gate = ArmourGate.production(
    policy,
    approval_verifier=approval_verifier,
    approval_ledger=approval_ledger,
)

decision = gate.evaluate(proposal, approval=approval)
```

Production construction rejects the configuration unless all five conditions
are true: a trusted approval verifier is present, the approval ledger is
durable, the verifier declares isolated signing authority, and the ledger
declares integrity protection, and every allowed action has a strict
host-owned `ActionSchema`. `Ed25519ApprovalVerifier` plus a keyed
`SQLiteApprovalLedger` is the reference configuration; an equivalent custom
implementation must provide the same declared properties and behaviour.

`Ed25519ApprovalVerifier` supports key rotation by accepting an explicit map of currently trusted public keys; removing a key ID revokes future approvals from it. The dependency-free `HMACApprovalVerifier` remains available for development or environments where the evaluator is intentionally trusted with the shared signing secret. `SQLiteApprovalLedger` atomically consumes approval nonces across process restarts and multiple Armour processes sharing the same database. Policy and key changes do not reset nonce history. Production construction fails closed unless signing authority is isolated from the evaluator and replay storage is both durable and authenticated. A host-provided monotonic `ApprovalCheckpoint` is additionally required to detect replacement by an older, valid ledger.

The integrity key must be at least 32 bytes, remain outside SQLite, and remain stable across restarts. An existing unsealed ledger is rejected by default. After independently validating that legacy database, an operator may open it once with `trust_existing_claims=True` to seal its current contents. This cannot prove the ledger was untampered before sealing. Automatic ledger-integrity-key rotation is not implemented.

Valid approvals are consumed by `evaluate()` by default, including when a caller uses the gate directly. `consume_approval=False` is an explicit preview mode; its result must never be treated as execution authority.

Signed approvals have a non-negotiable one-hour lifetime ceiling, and a gate
may configure a shorter maximum. The signed issuance timestamp must precede
expiry, and timestamps more than 30 seconds ahead of the gate's trusted clock
are rejected. `approval_clock` can be connected to a host-owned trustworthy
UTC time source. This bounds approval envelopes but does not make the local
clock rollback-proof; high-assurance deployments still need externally
protected time or a monotonic cross-restart anchor.

`security_report()` is an administrator-only diagnostic. Do not expose its
configuration inventory to an agent, proposal, remote caller, or ordinary
application log.

## Mutation testing and coverage

Armour includes an offline evaluation layer derived from SDCE's strongest idea: do not trust a verifier merely because expected examples pass; challenge it with bounded adversarial variants and measure which safety invariants were exercised.

```python
from armour import MutationRunner, STANDARD_INVARIANTS, standard_mutant_family

family = standard_mutant_family(proposal, policy)
report = MutationRunner(
    ArmourGate(policy),
    required_invariants=STANDARD_INVARIANTS,
).run(proposal, family)

assert report.passed
print(report.to_dict())
```

The standard family tests proposal-policy attacks plus production-construction violations, approval-ledger tampering and rollback, network-binding substitution, execution-binding freshness, security-memory integrity, quarantine and review controls, and Mirror Loop authorization, scope, hard ceilings, input types, display safety, and resource limits. It combines ordinary gate-evaluated proposal mutants with offline boundary probes for constructors, ledgers, memory, binders, and bounded deception. These probes never invoke `GuardedExecutor` or a registered handler. Applications should still add domain-specific mutants for their own tools and policies.

Mutation evaluation never executes a proposal through a registered handler. A
mutant is “killed” when its gate evaluation or boundary probe produces one of
the expected safe verdicts; surviving mutants and unexercised invariants fail
the report.

## Status

Early-stage research prototype and active work in progress. Policy integrity checks, HMAC and Ed25519 approval binding, durable atomic approval replay protection, staged receipt chains, explicit execution/audit outcomes, and the offline mutation harness are implemented and covered by the test suite. These tests are evidence about the cases exercised, not a security certification. Armour is not recommended for production or security-critical use at this stage; evaluation and use are entirely at the user's own risk.

Current verification snapshot: 174 unit tests pass and all 31 modeled mutants
are killed with full modeled-invariant coverage. This is self-adversarial test
evidence, not an independent human security audit or proof of general safety.

## Files

| Path | What it does |
| --- | --- |
| `armour/models.py` | Typed proposals, approvals, decisions, and fingerprints |
| `armour/approvals.py` | HMAC and separated Ed25519 approval provenance |
| `armour/policy.py` | Human-owned action, effect, filesystem, network, and risk policy |
| `armour/schemas.py` | Strict host-owned payload contracts for individual actions |
| `armour/verifiers.py` | Mandatory deterministic checks |
| `armour/gate.py` | Fail-closed verdict aggregation and approval validation |
| `armour/ledger.py` | Atomic in-memory and durable SQLite approval replay protection |
| `armour/executor.py` | Registered-handler execution boundary |
| `armour/binding.py` | Single-use proposal/policy/execution-scoped capability lifecycle |
| `armour/filesystem_binding.py` | Already-open, no-follow read capability |
| `armour/network_binding.py` | Preconnected, public-destination GET/HEAD capability |
| `armour/audit.py` | Hash-chained JSONL receipts and optional local checkpoints |
| `armour/evaluation.py` | Offline mutant families and invariant coverage |
| `armour/safe_filesystem.py` | Directory-relative, no-follow file primitives |
| `docs/THREAT_MODEL.md` | Trusted base, defended cases, and residual risks |

## Honest limitations

- Armour is not an operating-system, container, process, or bytecode sandbox.
- Registered handlers remain trusted code and can violate policy if incorrectly written.
- Ordinary filesystem and network handlers retain time-of-check/time-of-use
  risks. Bound handlers reduce path and DNS substitution only when they use the
  supplied capability; trusted handlers can bypass binders by performing their
  own I/O.
- Filesystem binding does not freeze contents of an opened inode or prevent
  access through hard-link aliases.
- `NetworkBinder` requires certificate verification and hostname checking at
  construction and rechecks its mutable TLS context before preparation.
- Network binding has controlled socket tests but no live HTTPS integration
  test yet.
- HMAC approval verification does not isolate signing authority from the evaluator and is rejected by production construction; use Ed25519 or an equivalent verifier that keeps signing authority outside the evaluator.
- Armour validates configured public keys but does not operate a certificate authority, distribute keys, or automatically expire signing keys.
- Development mode uses process-local replay protection unless `SQLiteApprovalLedger` is supplied; production mode refuses that fallback.
- SQLite protects concurrent processes sharing one database file, not hosts that do not share an atomic store.
- Direct replay-ledger edits fail closed when the production integrity key remains secret. Detecting replacement by an older valid ledger additionally requires a monotonic `ApprovalCheckpoint` outside SQLite's rollback boundary.
- Approval-ledger integrity currently hashes all claims in the deployment
  namespace on each operation. Growth is now fail-closed at 10,000 claims by
  default (configurable only up to a hard 100,000 ceiling), but performance
  still requires testing before choosing a deployment limit. Armour does not
  automatically delete replay history.
- Pattern scanning is defense in depth, not semantic proof. Production mode
  requires a strict schema for every action, and registered handlers must
  never execute model-controlled text as shell, SQL, Python, or other code.
- Approval expiry depends on the configured trusted UTC clock. The signed
  lifetime and future-timestamp limits reduce exposure but do not defeat a
  compromised clock that remains inside the signed validity interval.
- Armour cannot protect information already sent to a cloud model.
- Receipt hash chaining cannot prevent deletion or a complete attacker-rehashed
  rewrite. Optional checkpoints detect primary-log loss or replacement only if
  the attacker cannot also alter the checkpoint.
- Receipt and checkpoint locking is per `ReceiptLog` instance; other instances
  in the same process and writers in separate processes are not coordinated.
- A crash after the primary receipt is flushed but before its checkpoint is
  flushed leaves a detectable mismatch that requires operator recovery.
- A completion-audit failure is reported separately from handler success. Hosts
  still need idempotent handlers or downstream idempotency keys to recover safely
  from process crashes and ambiguous external effects.

See [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) for the complete boundary.

## Development

```bash
python -m unittest discover -s tests -v
```

## Origin

Armour was extracted from the useful safety architecture discovered while building Irene. It keeps the proposal/verification/governance/execution separation while deliberately excluding Irene-specific identity and autonomy components.

The evaluation layer retains the useful mutation-family and coverage-audit ideas from SDCE v0.3 while excluding its claimed in-process “sandbox,” placeholder oracle behavior, and non-comparative consensus check. See `docs/THREAT_MODEL.md` and `docs/IRENE_EXTRACTION.md` for the boundaries.

## License

Licensed under [PolyForm Noncommercial 1.0.0](./LICENSE)—free for personal use, research, evaluation, and testing. Commercial use requires a separate license; contact the author to discuss commercial licensing.
