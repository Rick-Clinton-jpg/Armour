# Armour verification protocol

Armour uses explicit verification labels so that passing tests are not
overstated as independent proof or external enforcement.

## Evidence levels

1. **Self-tested** — the builder wrote and ran expected-behaviour tests.
2. **Self-adversarially tested** — the builder designed hostile probes with
   knowledge of the implementation.
3. **Reproducibly verified** — a separate environment reproduced a fixed suite
   against an immutable commit.
4. **Independently reviewed** — a reviewer designed additional tests without
   receiving the builder's private reasoning, expected weaknesses, or attack
   paths. The reviewer may inspect the code under review.
5. **Externally enforced** — an independent operating-system, hardware, or
   service boundary enforces the claimed property even if the component stops
   cooperating.
6. **Formally verified** — a precisely stated property has a mathematical or
   machine-checked proof under a documented model and assumptions.

These levels are cumulative only when each lower level actually occurred. A
second model review is independent review only when its test design is not
seeded with the builder's conclusions. It is not formal verification or
external enforcement.

## Review-readiness gate

A change may be labelled `REVIEW_READY` only when all of the following are
recorded against one local commit:

- security invariants were written as failing tests before the fix
- the focused invariant tests pass
- the full unit suite passes without unexpected failures
- the standard mutation family kills every required mutant with full invariant
  coverage
- `git diff --check` passes
- the threat model states both the guarantee and its remaining assumptions
- the commit hash and exact commands needed to reproduce the results are known

`REVIEW_READY` is a technical status, not permission to publish. Pushing a
branch still requires repository-owner authorization. After publication,
remote CI must reproduce the suite before independent review begins.

## Independent-review handoff

Provide the reviewer only:

- the immutable commit hash
- the public security claims and threat model
- installation and test commands
- the expected result format

Do not provide private implementation reasoning, the builder's discovered
weaknesses, or suggested attack cases until the reviewer records their initial
results. Preserve those results before making responsive code changes.
