# Crash Capsule privacy registry

Generated from `specification/registry.toml` by `cargo run -p cc-vectors`. Do not edit.

Schema version: 1.0

A field's effective class is `max(schema minimum class, producer declared class)`. A producer may raise a classification; it can never lower one.

## Classes

| Class | Meaning |
| --- | --- |
| P0 | Normally safe to disclose: schema version, failure class, versions, function names. |
| P1 | Can contribute to fingerprinting or device profiling: coarse hardware IDs, module set, distro, taint. |
| P2 | Likely to identify user or system: hostnames, IP addresses, user paths, process arguments. Redacted or tokenised by default. |
| P3 | May contain credentials or private content: environment, arbitrary log text, headers. Omitted unless explicitly justified. |
| P4 | Essentially uncontrolled memory or content: core dumps, process memory, full journals. Never optical by default. |

## Profiles

| Profile | Id | Target bytes | Hard limit | Max class |
| --- | --- | --- | --- | --- |
| `panic-minimal` | 0 | 1536 | 2560 | P1 |
| `visual-small` | 1 | 4096 | 8192 | P1 |
| `visual-standard` | 2 | 12288 | 16384 | P1 |
| `visual-extended` | 3 | 32768 | 32768 | P2 |
| `local-full` | 4 | 262144 | 262144 | P3 |

## Fields

| Path | Key | Type | Class | Required | Description |
| --- | --- | --- | --- | --- | --- |

## Evidence kinds

| Kind | Id | Minimum class |
| --- | --- | --- |
| `normalised-log-template` | 0 | P1 |
| `module-list` | 1 | P1 |
| `structured-context` | 2 | P1 |
| `raw-log-text` | 3 | P3 |
| `artifact-reference` | 4 | P1 |
| `core-dump` | 5 | P4 |

## Never collected by default

Serial numbers, machine UUIDs, motherboard identifiers, MAC addresses, IP addresses, SSIDs, hostnames, DNS names, URLs, argv, environment variables, the current working directory, file contents, process memory and full journals. Core dumps are P4 and are referenced by hash, never embedded in a transported capsule.
