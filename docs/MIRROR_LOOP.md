# Mirror Loop experimental design

Mirror Loop is an opt-in, bounded deception mechanism for proposals that Armour
has already rejected or escalated. It accepts attempted commands as inert text,
returns a deterministic reflection, and records data-only evidence. It never
executes the text.

```text
untrusted proposal -> Armour decision -> REJECTED / ESCALATED
                                              |
                                              v
                                      bound Mirror Loop
                                              |
                        terminal -> filesystem -> network -> mirror
                           ^                         |
                           +---- filesystem <- network
                                              |
                                  limit reached / mismatch
                                              v
                                          terminate
                                              |
                                      evidence for review
```

## Enforced invariants

- An authorized action cannot be diverted into this mechanism.
- A session is bound to the proposal fingerprint, policy fingerprint, and
  execution ID that created it.
- A mismatch or expired deadline permanently terminates the session.
- Step, repetition, per-attempt byte, total-byte, and wall-clock limits can be
  tightened by the host but cannot exceed Armour's absolute ceilings: 64 steps,
  eight repeats, 64 KiB per attempt, 256 KiB total, and 10 seconds.
- Reflected content is returned only as a typed `ControlEscapedReflection`. Active
  Unicode and terminal controls are replaced by visible `<U+XXXX>` tokens. The
  value remains untrusted, needs output-context-specific escaping, and has no
  decode or execution operation.
- This module has no shell, interpreter, filesystem, network, subprocess,
  handler, or callback execution path.
- Evidence stores attempt hashes rather than the submitted text and is not
  automatically promoted into security memory or the mutation suite.

## What it does not guarantee

Mirror Loop is not an operating-system sandbox, container, virtual machine, or
network boundary. It does not make a real terminal safe. A host that gives the
same agent another shell, socket, credential, file descriptor, or trusted
handler has created a route around the chamber. The current implementation is a
safe state-machine core for testing the concept; deployment requires a genuinely
isolated process or micro-VM with no inherited credentials and deny-by-default
egress.

The state path is deception, not the security wall. A model can recognize the
simulation, produce new attempts, or refuse to participate. Safety comes from
the absence of real capabilities and unconditional resource limits—not from
confusing the model. Reflections must never be passed to an evaluator, shell, or
interpreter by calling code.

The deadline uses a host-provided monotonic clock for deterministic testing and
therefore cannot defend against a compromised or frozen host clock. A real
chamber requires an external watchdog. Verification status terminology is
defined in [the portfolio verification protocol](VERIFICATION_PROTOCOL.md).
