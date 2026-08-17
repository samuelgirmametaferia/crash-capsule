# crash-capsule

A common diagnostic protocol for Linux failures. Kernel panics, oopses, userspace crashes,
service failures and boot failures all produce the same artefact: a small, structured,
privacy-classified **capsule** that can travel over HTTPS, sit on disk, or be read off a screen
with a camera when the machine cannot reach the network at all.

A capsule is deliberately not a core dump and not a journal excerpt. It is a few kilobytes of
evidence with a stable identity.

## Status

Foundation only. The protocol core is implemented and covered by a published test corpus; the
producers, transports, decoder and backend are not built yet — see
[`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).

| Component | State |
| --- | --- |
| Schema registry, wire keys, privacy floors | implemented |
| Deterministic CBOR encoder + strict bounded decoder | implemented |
| Strict and family fingerprints (`ccfp/1`) | implemented |
| Capsule model, validation, evidence budget | implemented |
| Specification and 60+ test vectors | published |
| Producers, daemon, optical transport, PWA, backend | not started |

## What makes it work

- **Deterministic CBOR.** Byte-exact across implementations, which is what makes hashing the
  encoding — and therefore exact deduplication — sound.
- **Two fingerprints.** Strict answers "same crash, same build"; family answers "probably the
  same bug across builds". Fuzzy similarity is advisory and never merges anything by itself.
- **Privacy is mechanical, not a policy document.** Every field has a minimum class in
  `specification/registry.toml`, the Rust constants are generated from it, and the effective
  class is `max(registry floor, producer declaration)` — a producer can raise a class, never
  lower one.
- **Budgets that never sacrifice identity.** Over-size capsules drop evidence by priority; the
  event, frames and fingerprints always survive.
- **A camera is a valid transport.** Visual profiles are capped at P1 (P2 for the explicitly
  slower extended profile), so what a bystander can photograph is bounded by construction.

## Specification

| Document | |
| --- | --- |
| [`crash-capsule.cddl`](specification/crash-capsule.cddl) | The wire format |
| [`registry.toml`](specification/registry.toml) | Normative keys, classes and budgets |
| [`privacy-registry.md`](specification/privacy-registry.md) | Generated, human-readable view of the above |
| [`fingerprint-v1.md`](specification/fingerprint-v1.md) | `ccfp/1` |
| [`visual-envelope.cddl`](specification/visual-envelope.cddl) | Optical transport framing |
| [`threat-model.md`](specification/threat-model.md) | Adversaries, non-goals, and the rules that answer them |
| [`extension-registry.md`](specification/extension-registry.md) | How the schema evolves |
| [`test-vectors/`](specification/test-vectors) | The conformance corpus |

## Building

```bash
cargo test --workspace
cargo run -p cc-vectors    # regenerates the corpus; must produce no diff
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/architecture.md`](docs/architecture.md).

## Licence

MIT.
