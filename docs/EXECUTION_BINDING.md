# Execution-Bound Evidence

Status: experimental design for the filesystem-only first implementation.

## Problem

Armour can validate a path and its policy before execution, but an ordinary
handler may later reopen that path by name. A hostile local process can replace
a checked path component between those events. A timestamp only limits the
race; it does not make the checked object and used object identical.

## Security objective

Execution-Bound Evidence (EBE) binds an authorized execution to host-owned,
single-use runtime capabilities prepared for the exact proposal and policy.
The first implementation covers read-only filesystem resources and supplies an
already-open, no-follow file capability to an explicitly registered bound
handler.

This is an identity-binding guarantee, not a claim that all resource state is
frozen. An opened file can retain its inode while another process changes its
contents. Authorization can also be revoked after a capability is prepared.
The host and handler remain inside Armour's trusted computing base.

## Design goals

**EBE ensures the handler receives the same resource identity that Armour
verified, provided the registered handler uses the supplied capability —
deadlines and state/version checks remain necessary where authorization or
contents can change.**

- Fail closed when required policy dependencies or binders are missing.
- Keep dependency classification and maximum age in host-owned `Policy`, never
  in an agent-controlled proposal.
- Include dependency policy in the policy fingerprint so a change invalidates
  prior approvals.
- Bind evidence to one proposal fingerprint, policy fingerprint, execution ID,
  and consumption event.
- Use a monotonic clock for local validity windows.
- Give a bound handler the prepared capability, not merely the checked path.
- Close every prepared capability after success or any failure.
- Preserve Armour's existing distinction between handler success and audit
  completion success.
- Preserve existing unbound actions for compatibility, but reject ordinary
  handler registration when an action's policy requires bound dependencies.
- Allow observed latency to recommend a tighter deadline only. No runtime
  observation may enlarge the host-owned policy ceiling.

## Non-goals for the first implementation

- Network, DNS, API, database, credential, or cross-process capabilities.
- Automatic latency learning or policy mutation.
- Durable or transferable evidence tokens.
- Freezing mutable file contents.
- Preventing a trusted Python handler from deliberately ignoring its supplied
  capability and performing unrelated I/O.
- Replacing an operating-system sandbox.

## State model

1. `ArmourGate` evaluates the immutable proposal and consumes any required
   human approval.
2. `GuardedExecutor` creates a fresh execution ID.
3. Host-registered binders prepare every dependency required by the policy.
4. The executor writes the `started` receipt.
5. Immediately before calling the handler, the executor atomically consumes
   the binding and checks proposal, policy, execution ID, and monotonic expiry.
6. The bound handler receives an `ExecutionContext` containing the capability.
7. The executor closes the context on every exit path and writes completion
   evidence without rewriting handler success if that audit write fails.

An approval may be consumed even if later capability preparation fails. This
is deliberately fail-closed: a valid approval is authorization for one attempt,
not a reusable credential. Improving availability here would require a larger
transaction spanning approval claim, capability preparation, and execution.

## Filesystem capability

The filesystem binder accepts only `ActionProposal.resource`, requires it to be
inside a configured policy root, opens every component relative to directory
file descriptors with no-follow controls, verifies that the result is a regular
file, and records its device/inode identity. The bound handler reads from that
descriptor. Replacing the pathname afterward cannot redirect the descriptor to
a different inode.

The file capability checks its monotonic deadline again at actual access. This
limits delayed use but does not freeze data stored in the same inode.

## Security invariants

1. Exact proposal binding.
2. Exact policy binding.
3. Exact execution binding.
4. Single-use binding consumption.
5. Agent cannot choose dependency class or extend maximum age.
6. Missing or mismatched binders prevent handler execution.
7. Expired evidence prevents handler execution.
8. Cross-proposal transplantation fails.
9. All capabilities close on success and every failure path.
10. Path replacement after preparation cannot redirect file access.
11. Audit-start failure prevents execution.
12. Audit-completion failure preserves the real handler result.

## Future work

Network binding requires a connection or authenticated peer capability, not a
cached DNS result. External APIs require server-enforced versions, ETags, or
transaction preconditions. Those designs will be reviewed separately after the
filesystem abstraction survives adversarial testing.
