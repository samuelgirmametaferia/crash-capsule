# Extension registry

Crash Capsule evolves additively. This document defines how, and records what has been
allocated.

## Rules

- **Adding** a field, profile, source kind, failure class, evidence kind or category is a
  `schema_minor` change. Readers ignore keys they do not know.
- **Changing** a key number or type, or **lowering** a privacy class, is a `schema_major`
  change. It requires new test vectors in the same pull request.
- A feature that a reader *must* understand to interpret a capsule correctly needs a bit in
  `capsule.critical_features`. Readers reject capsules with unknown critical bits rather than
  interpreting them partially. Allocating a critical bit is a `schema_minor` change for
  producers and a breaking change in practice for old readers — that is the point, and it is
  why the bit exists.
- Unknown non-critical keys SHOULD be retained when a capsule is forwarded, so that an
  intermediary does not silently strip information from a newer producer.

## Key space

| Range | Use |
| --- | --- |
| 0–1023 | Standard keys, allocated in `specification/registry.toml` |
| 1024–65535 | Registered vendor extensions, allocated in this document |
| 65536+ | Private and experimental; MUST NOT be relied on across implementations |

## Critical feature bits

| Bit | Name | Status |
| --- | --- | --- |
| — | — | None allocated in schema 1.0 |

## Registered vendor extensions

| Key | Owner | Description | Class |
| --- | --- | --- | --- |
| — | — | None registered | — |

## Requesting an allocation

Open a pull request that adds the row here, adds the field to `specification/registry.toml`
where applicable, regenerates the corpus with `cargo run -p cc-vectors`, and states the privacy
class with a justification. A field with no privacy justification will not be merged.
