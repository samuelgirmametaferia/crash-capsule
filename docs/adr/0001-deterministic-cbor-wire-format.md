# ADR 0001: Deterministic CBOR as the wire format

- **Status:** accepted
- **Date:** 2026-08-17

## Context

A capsule has to survive three transports with very different constraints: HTTPS, a file on
disk, and a camera pointed at a screen. The optical path caps the compressed payload at 32 KiB
and, more importantly, means the same logical capsule may be encoded by a kernel-adjacent
producer, a Rust daemon and eventually a phone, then decoded by a browser.

Two properties follow from that:

1. **Byte-exact reproducibility.** Fingerprints are hashes over the encoding, and exact
   deduplication compares them. Two implementations that encode the same capsule differently
   produce different fingerprints, and deduplication silently stops working.
2. **Hostile-input safety.** A decoder in a browser parses bytes that came off an unknown
   screen.

## Decision

The wire format is CBOR restricted to a deterministic profile: definite lengths only,
shortest-form arguments, map keys sorted bytewise on their encoded form, no duplicate keys, no
tags, no floats, no simple values beyond `true`/`false`/`null`. Keys are integers allocated in
`specification/registry.toml`. The grammar lives in `specification/crash-capsule.cddl`; the
reference encoder and a bounded strict decoder live in `cc-canonical`.

The decoder rejects rather than repairs, and bounds depth, item count, string length and total
input before allocating.

## Alternatives rejected

- **JSON.** Not byte-reproducible in practice (number formatting, key order, escaping), and
  roughly twice the size on this data — which directly costs optical transfer time.
- **Protobuf.** Canonical serialisation is explicitly not guaranteed, so hashing the encoding is
  unsound. Also awkward for the `evidence.value` field, which is genuinely dynamic.
- **A bespoke binary format.** We would have written a parser anyway, but without CDDL, without
  existing tooling, and without COSE for the authenticated envelope.
- **Full CBOR.** Tags, floats and indefinite lengths add attack surface and non-determinism for
  no benefit here; nothing in the schema needs them.

## Consequences

- Every implementation must implement the same restricted subset; generic CBOR libraries are
  not automatically conformant. The committed corpus exists precisely to catch that.
- Adding a key is cheap and non-breaking; renumbering one is a `schema_major` change.
- COSE composes naturally, since it is CBOR-native.
- Hashing the encoding is sound, which is what makes strict fingerprints work.
