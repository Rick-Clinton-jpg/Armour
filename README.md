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
        └─ dangerous-content rejection
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
executor.register("read_note", lambda proposal: Path(proposal.resource).read_text())

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
- High-risk actions require separately supplied human approval.
- Approvals bind to the proposal ID, exact arguments, policy fingerprint, approving identity, expiry, and a single-use nonce.
- Filesystem paths must be absolute and remain beneath explicit roots after resolution.
- Optional `ActionSchema` contracts reject unknown payload keys and identify the exact filesystem fields shared by verification and the registered handler.
- Network destinations are restricted to GET/HEAD and checked after DNS resolution for private, loopback, link-local, reserved, and otherwise non-public addresses.
- Execution is limited to host-registered Python callables; proposals cannot contain executable handlers.
- Every decision and outcome can be written to a hash-chained JSONL receipt log.

Armour is a policy boundary, not a complete sandbox. Host handlers remain trusted code and must avoid time-of-check/time-of-use mistakes—for example, re-resolve network destinations at connection time and use directory-relative file APIs when hostile local filesystem races are possible.

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
)
gate = ArmourGate.production(
    policy,
    approval_verifier=approval_verifier,
    approval_ledger=approval_ledger,
)

decision = gate.evaluate(proposal, approval=approval)
```

`Ed25519ApprovalVerifier` supports key rotation by accepting an explicit map of currently trusted public keys; removing a key ID revokes future approvals from it. The dependency-free `HMACApprovalVerifier` remains available for environments where the evaluator is trusted with the shared signing secret. `SQLiteApprovalLedger` atomically consumes approval nonces across process restarts and multiple Armour processes sharing the same database. Policy and key changes do not reset nonce history. Production construction fails closed unless both trusted approval verification and durable replay storage are configured.

Valid approvals are consumed by `evaluate()` by default, including when a caller uses the gate directly. `consume_approval=False` is an explicit preview mode; its result must never be treated as execution authority.

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

The standard family tests unknown actions, forbidden effects, root escape, private-network access, dangerous command content, request-risk downgrading, and—when configured—a model understating the effect of a destructive action. Applications should add domain-specific mutants for their own tools and policies.

Mutation evaluation never executes a proposal. A mutant is “killed” when the gate produces one of the mutation's expected safe verdicts; surviving mutants and unexercised invariants fail the report.

## Status

Early-stage research prototype and active work in progress. Policy integrity checks, HMAC and Ed25519 approval binding, durable atomic approval replay protection, staged receipt chains, and the offline mutation harness are implemented and covered by 57 tests. These tests are evidence about the cases exercised, not a security certification. Armour is not recommended for production or security-critical use at this stage; evaluation and use are entirely at the user's own risk.

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
| `armour/audit.py` | Hash-chained JSONL receipts |
| `armour/evaluation.py` | Offline mutant families and invariant coverage |
| `docs/THREAT_MODEL.md` | Trusted base, defended cases, and residual risks |

## Honest limitations

- Armour is not an operating-system, container, process, or bytecode sandbox.
- Registered handlers remain trusted code and can violate policy if incorrectly written.
- Filesystem and DNS checks have time-of-check/time-of-use risks that handlers must address.
- HMAC approval verification does not isolate signing authority from the evaluator; use the optional Ed25519 signer/verifier when that separation is required.
- Armour validates configured public keys but does not operate a certificate authority, distribute keys, or automatically expire signing keys.
- Development mode uses process-local replay protection unless `SQLiteApprovalLedger` is supplied; production mode refuses that fallback.
- SQLite protects concurrent processes sharing one database file, not hosts that do not share an atomic store.
- Pattern scanning is defense in depth, not semantic proof.
- Armour cannot protect information already sent to a cloud model.
- Receipt hash chaining detects modification but cannot prevent deletion of the entire receipt file.

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
