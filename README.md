# Armour

Armour is a deterministic safety boundary for AI agents.

An agent may plan freely and propose actions. Armour—not the agent—decides whether each action is authorized, rejected, or requires explicit human approval. Armour contains no LLM, autonomy loop, personality, memory system, shell executor, or self-modification mechanism.

## Install

Armour requires Python 3.11+ and has no runtime dependencies.

```bash
git clone https://github.com/Rick-Clinton-jpg/Armour.git
cd Armour
pip install -e .
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
    HumanApproval,
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
- Network destinations are restricted to GET/HEAD and checked after DNS resolution for private, loopback, link-local, reserved, and otherwise non-public addresses.
- Execution is limited to host-registered Python callables; proposals cannot contain executable handlers.
- Every decision and outcome can be written to a hash-chained JSONL receipt log.

Armour is a policy boundary, not a complete sandbox. Host handlers remain trusted code and must avoid time-of-check/time-of-use mistakes—for example, re-resolve network destinations at connection time and use directory-relative file APIs when hostile local filesystem races are possible.

Raw model JSON should enter through `ActionProposal.from_untrusted(...)`. Human approval is represented by a `HumanApproval` bound to one exact proposal and policy version; the host—not the model—must create it through a separate trusted interaction.

```python
approval = HumanApproval.issue(
    proposal,
    policy_fingerprint=policy.fingerprint(),
    approved_by="rick@example.com",
    ttl_seconds=120,
)
outcome = executor.execute(proposal, approval=approval)
```

The built-in nonce ledger prevents replay inside one running `ArmourGate`. A production deployment with multiple processes must provide a shared durable approval store before treating this as cross-process replay protection.

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

Early-stage research prototype. The policy boundary, approval binding, receipt chain, and offline mutation harness are implemented and covered by 28 tests. Armour is suitable for experimentation and integration work, but it is not yet a production security boundary.

## Files

| Path | What it does |
| --- | --- |
| `armour/models.py` | Typed proposals, approvals, decisions, and fingerprints |
| `armour/policy.py` | Human-owned action, effect, filesystem, network, and risk policy |
| `armour/verifiers.py` | Mandatory deterministic checks |
| `armour/gate.py` | Fail-closed verdict aggregation and approval validation |
| `armour/executor.py` | Registered-handler execution boundary |
| `armour/audit.py` | Hash-chained JSONL receipts |
| `armour/evaluation.py` | Offline mutant families and invariant coverage |
| `docs/THREAT_MODEL.md` | Trusted base, defended cases, and residual risks |

## Honest limitations

- Armour is not an operating-system, container, process, or bytecode sandbox.
- Registered handlers remain trusted code and can violate policy if incorrectly written.
- Filesystem and DNS checks have time-of-check/time-of-use risks that handlers must address.
- Approval replay protection is process-local; distributed deployments need an atomic shared store.
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
