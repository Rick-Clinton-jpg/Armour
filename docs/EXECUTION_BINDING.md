# Execution-Bound Evidence

Status: experimental implementation for read-only filesystem and HTTP(S)
dependencies.

## Problem

Armour can validate a path and its policy before execution, but an ordinary
handler may later reopen that path by name. A hostile local process can replace
a checked path component between those events. A timestamp only limits the
race; it does not make the checked object and used object identical.

## Security objective

Execution-Bound Evidence (EBE) binds an authorized execution to host-owned,
single-use runtime capabilities prepared for the exact proposal and policy.
The implementation covers read-only filesystem resources and read-only HTTP(S)
requests. It supplies an already-open, no-follow file or an already-connected
HTTP capability to an explicitly registered bound handler.

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

## Non-goals

- General API, database, credential, state-changing network, or cross-process
  capabilities.
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

## Network capability

`NetworkBinder` supports HTTP and HTTPS with GET and HEAD only. Preparation
extracts the URL and method from the proposal, checks them against the
host-owned network policy, resolves the hostname exactly once, and rejects the
entire result if any returned address is private, loopback, link-local,
reserved, or otherwise non-public. It then opens a socket directly to one
verified numeric address. HTTPS verifies the certificate against the original
hostname and sends that hostname through normal HTTP handling. A custom
`ssl.SSLContext` is accepted only when `CERT_REQUIRED` and hostname checking
are active. Because contexts are mutable, Armour checks those properties both
at binder construction and immediately before preparation; weakening the
context in between fails closed before a connection is opened.

The handler receives `BoundNetworkConnection`, not a URL or a cached DNS
verdict. Its `request()` method takes no destination, method, headers, or body,
so the handler cannot substitute those values through the capability. The
method and request target were fixed during preparation, and the socket was
already connected to the verified peer. A later DNS change therefore cannot
redirect that request. HTTP redirect responses are returned to the handler but
are never followed by the capability.

Both the enclosing execution binding and the network capability check the
monotonic deadline. The capability permits one request attempt, including when
the attempt fails, and closes on every executor exit path. Response bodies are
bounded by a host-configured limit (8 MiB by default).

This guarantee is deliberately narrow:

- It applies only when the registered handler uses the supplied capability. A
  trusted handler can still open an unrelated socket because Armour is not a
  process sandbox.
- It binds the connection's peer IP, original hostname, method, port, and
  request target for one request. It does not prove that remote content or
  authorization remains unchanged.
- A public service can itself proxy, forward, or return attacker-controlled
  content. Public addressing is not a claim that the remote service is safe.
- DNS resolution, connection establishment, and TLS occur in the Armour
  process. The capability is not transferable across processes.
- Network tests use controlled connections and do not yet include a live HTTPS
  integration test of DNS, TCP, TLS, and certificate validation together.
- The maximum-age check happens immediately before request transmission. It
  does not cancel an in-flight request when the age boundary passes; the
  separately configured socket timeout bounds that operation.
- Custom API authentication, request bodies, caller-selected headers,
  automatic redirects, and state-changing methods are intentionally not
  supported.

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
13. Every resolved network address must be public.
14. A bound network request uses the already-connected verified peer and cannot
    be redirected by a later DNS substitution.
15. A network capability permits exactly one fixed GET or HEAD attempt and
    never follows redirects.

## Future work

External API mutation requires server-enforced versions, ETags, idempotency
keys, or transaction preconditions; a pinned connection alone is insufficient.
Database, credential, cross-process, and state-changing network capabilities
need separate designs and adversarial review.
