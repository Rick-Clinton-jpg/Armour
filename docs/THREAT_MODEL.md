# Armour threat model

## Security objective

An untrusted model may propose actions and arguments. It must not be able to make an unregistered, out-of-scope, forbidden, or insufficiently approved side effect cross into a trusted handler merely by changing its output.

## Trusted computing base

- the host application and process
- `Policy` construction and storage
- Armour's mandatory verifier chain and gate
- registered handler implementations
- the human-approval issuance channel
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
- expired, mismatched, or same-process replayed approvals
- unsigned approvals and approvals signed by unknown HMAC keys
- receipt modification detectable through a hash chain
- an execution-started receipt written before an authorized handler runs

## Explicit non-goals and residual risks

- Armour is not an operating-system, container, process, or bytecode sandbox.
- Registered handlers are trusted and can violate policy if incorrectly written.
- A path can change between verification and handler access; high-assurance handlers should use directory-relative file descriptors and platform-specific no-follow controls.
- A hostname can resolve differently between verification and connection; network handlers must pin or re-verify the actual connected address.
- The built-in approval nonce ledger is process-local and resets on restart. Distributed deployments need an atomic shared store.
- The reference HMAC verifier shares signing authority with the evaluator. Use a public-key `ApprovalVerifier` when approval issuance must remain isolated from that process.
- Pattern scanning cannot establish semantic safety and is only defense in depth.
- Armour does not protect information already sent to a cloud model.
- It authenticates configured approval keys, not the real-world identity behind them; it does not sign policies, manage credentials, or enforce resource quotas yet.
- Hash chaining exposes tampering but does not prevent deletion of the entire receipt file; external anchoring is required for stronger audit guarantees.

## Evaluation rule

Runtime tests prove expected cases. Mutation tests challenge the boundary with named adversarial variants and measure both mutation score and invariant coverage. Neither is a mathematical proof of safety; unmodeled failure families remain possible and should be added when discovered.
