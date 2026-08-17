# Crash Capsule threat model

## What we are protecting

1. **The reporting user's privacy.** A capsule is generated at the worst possible moment, by
   software the user is not thinking about, and may be photographed off a screen by a stranger.
2. **The integrity of triage.** A maintainer must not be able to be tricked into merging,
   routing or trusting a fabricated report.
3. **The availability of the crashing system.** Reporting must never be the reason a machine
   fails to boot or a panic path deadlocks.

## Adversaries

| Adversary | Capability | Primary mitigation |
| --- | --- | --- |
| Bystander with a camera | Photographs the screen during an optical transfer | Visual profiles are capped at P1 (P2 for `visual-extended`); P3/P4 material is never rendered optically |
| Malicious capsule author | Submits crafted capsules to the backend | Bounded strict decoder; capsules are data, never code; no automatic public disclosure |
| Malicious display | Renders hostile frames at a decoder | Payload is authenticated with COSE; dynamic payloads may never open a URL; FEC output is not trusted until verification |
| Curious backend operator | Reads stored capsules | Client-side redaction happens before transport, so the backend never receives what was dropped; a second server-side pass prevents persistence of anything that slipped through |
| Network observer | Sees capsule traffic | TLS for transport; capsule payload is separately authenticated so a terminating proxy cannot alter it |
| Compromised producer on the reporting host | Emits capsules claiming to be another component | Capsules are attributed, not trusted; server-side classification is recomputed, never taken from the producer |

## Non-goals

- Protecting against an adversary who already has root on the reporting machine. They can read
  the crash directly.
- Anonymity. A capsule is pseudonymous at best; the privacy classes describe *risk*, not a
  guarantee of unlinkability.
- Preventing a determined user from deliberately including their own secrets in a `local-full`
  capsule they choose to send.

## The two redaction passes, and why both exist

Client-side redaction **prevents disclosure**: material dropped before transport cannot leak
from a server that is later breached. Server-side redaction **prevents persistence and
secondary disclosure**: it catches a producer that is buggy, out of date or hostile, and it
stops classified material from reaching an issue tracker. Neither pass is sufficient alone, and
the server never trusts the producer's classification — it recomputes the floor from the
registry.

## Specific hazards and the rules that answer them

**Fail-open parsing.** A decoder that guesses at a capsule it does not fully understand can be
steered. Unknown *critical* feature bits therefore cause rejection, not best-effort handling.

**Resource exhaustion during decode.** Hostile CBOR can declare a four-gigabyte string in five
bytes. The decoder bounds depth, item count, string length and total input, and never allocates
on a declared length that exceeds the remaining input.

**FEC mistaken for integrity.** Reed–Solomon reassembly succeeding says nothing about
authenticity. Verification of the reassembled payload is mandatory and final.

**URL injection through the optical channel.** A dynamic frame that could carry a URL turns a
camera into a phishing vector. Only the static bootstrap QR carries a URL, and it points at a
fixed, verified endpoint.

**Fingerprint collision as a merge attack.** An attacker who can force a fingerprint collision
can bury a report. Fingerprints are SHA-256 over domain-separated material, and fuzzy matching
is advisory only, so a merge always has a deterministic or human justification.

**Automatic disclosure of a security bug.** Publishing a crash in a security-sensitive
component is itself the vulnerability disclosure. Nothing is published to a public tracker
automatically; maintainer routing is manually approved, and raw capsules never appear in public
issues.

**The panic path.** Kernel-context reporting stays static, allocation-free, non-blocking and
bounded. Rich optical transfer is userspace-only, and Crash Capsule never installs itself as a
competing `kernel.core_pattern` handler.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md).
