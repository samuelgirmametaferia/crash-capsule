# Architecture

## The pipeline

```text
crash sources (kernel panic, oops, userspace crash, service failure, boot failure)
    -> producer builds a capsule
    -> schema validation
    -> privacy classification and redaction        [client-side: prevents disclosure]
    -> canonicalise + fingerprint
    -> compress (zstd)
    -> authenticate/encrypt (COSE)
    -> HTTPS | local encrypted store | optical transport
    -> triage backend
    -> second privacy pass                         [server-side: prevents persistence]
    -> symbolication
    -> exact (strict) and candidate (family) deduplication
    -> known-bug lookup
    -> security and routing policy, manually approved
```

## Crates

| Crate | Responsibility | Depends on |
| --- | --- | --- |
| `cc-schema` | Wire keys, profile budgets and privacy floors, **generated** from `specification/registry.toml` at build time | — |
| `cc-canonical` | Deterministic CBOR encoder and a strict, bounded decoder | — |
| `cc-fingerprint` | Strict and family fingerprints, `ccfp/1` | `cc-canonical` |
| `cc-capsule` | Typed object model, validation, evidence budget, fingerprint integration | the above |
| `cc-vectors` | Generates and verifies the published corpus | the above |

Nothing above `cc-schema` hard-codes a key number or a privacy class: the registry is the single
source of truth, and `build.rs` fails the build on a duplicate key. That is why a privacy rule
cannot be quietly bypassed by a new producer — it would have to change the registry, which is
reviewable.

## Invariants worth knowing before changing anything

**The registry floor wins.** `effective_class = max(registry floor, producer declaration)`.
A producer may raise a class; nothing can lower one. Enforced in `cc-schema` and applied by
`Evidence::effective_class`.

**Readers fail closed.** An unknown bit in `critical_features` is a rejection, not a
best-effort parse. Unknown *non-critical* keys are ignored, and retained when forwarding.

**Identity survives the budget.** When a capsule exceeds its profile, evidence is dropped —
first anything above the profile's class ceiling, then in ascending priority order. The event,
frames, fingerprints and privacy manifest are never dropped. A capsule that is still too large
with no evidence left is rejected rather than truncated.

**Nothing boot-local is fingerprinted.** `Frame` cannot express an absolute address, so this is
structural rather than a rule someone has to remember.

**The corpus is generated.** `specification/test-vectors/` and
`specification/privacy-registry.md` come from `cargo run -p cc-vectors`. CI fails if they drift,
so an encoder change that moves a byte is visible in review.

## Boundaries with the rest of the system

- `systemd-coredump` remains the `kernel.core_pattern` handler. Crash Capsule consumes its
  metadata and backtrace afterwards, and never competes for the hook.
- Core dumps are referenced by hash as a local artifact; they are P4 and are never embedded in
  a transported capsule.
- pstore/ramoops records are copied and durably committed before the source record is removed.
- Rich optical transfer is userspace-only. The panic path stays static, allocation-free,
  non-blocking and bounded.

## Not yet built

Producers and adapters (`systemd-coredump`, pstore), the daemon, the local encrypted store, the
optical transports, the PWA decoder, the triage backend and packaging. See
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for the phase order.
