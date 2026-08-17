# Security policy

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting on this repository, or
email the maintainer listed in `Cargo.toml`.

Please include the affected component, the impact, and — if the report involves a capsule — the
capsule's fingerprint rather than the capsule itself. We will ask for the raw material through a
private channel if we need it.

## What we consider a vulnerability

Beyond the usual memory-safety and authentication classes, the following are security bugs in
this project even though they may look like feature bugs:

- **Privacy-class escape.** Any path by which material at or above P2 reaches an optical
  transport, or P3/P4 material reaches a public artifact such as an issue tracker.
- **Producer-declared class being honoured below the registry floor.** The effective class must
  always be `max(registry floor, producer declaration)`.
- **A decoder accepting non-canonical CBOR**, or allocating on a declared length before it has
  the bytes.
- **Accepting a capsule with unknown critical feature bits.**
- **Treating FEC reassembly as integrity**, i.e. acting on a payload before its cryptographic
  verification succeeds.
- **A dynamic optical payload causing navigation** to an attacker-chosen URL.
- **Automatic public disclosure** of a capsule from a security-sensitive component.

## Handling security-sensitive crashes

A crash in a security-relevant component is itself sensitive information. Such capsules are
never published automatically, never attached to a public issue, and are routed only with
explicit maintainer approval.

## Supported versions

The project is pre-1.0. Only `main` receives fixes.
