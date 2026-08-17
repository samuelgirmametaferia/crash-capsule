# Crash Capsule — Full Implementation Plan

Derived from the technical blueprint ("Crash Capsule: A Technical Blueprint for Offline Linux Crash
Capture, Visual Transport and Automated Triage"). This document is the execution plan: what gets
built, in what order, by which component, and what "done" means for each step.

Guiding rule from the blueprint, kept as the north star of this plan:

> **The Crash Capsule is the protocol. The visual code is one transport profile of that protocol.**

Consequences that shape every phase below:

- The schema, privacy semantics and fingerprinting rules are frozen and tested *before* any
  transport or backend work, so the transport never accidentally defines the data model.
- The kernel panic path stays static, allocation-free and minimal; all rich/animated behaviour is
  userspace, post-reboot.
- Monochrome dynamic QR + Reed–Solomon outer FEC is the first deployable optical transport;
  RaptorQ and colour are explicitly later generations.
- No path exists from "user scanned a code" to "public tracker issue" without dedupe, a security
  gate and per-project opt-in policy.

---

## 0. Technology choices (decided up front)

| Layer | Choice | Rationale |
|---|---|---|
| Protocol core, daemon, encoders | Rust (stable, 2021 edition, workspace) | Memory safety on untrusted input; matches `drm_panic_qr.rs` for the future kernel boundary; good CBOR/zstd/COSE ecosystem |
| Wire format | Deterministic CBOR (RFC 8949 §4.2.1) + CDDL schema | Reproducible bytes for fingerprints; compact integer keys |
| Compression | Zstandard (RFC 8878), level 3, bounded window | Standardised, low latency; DEFLATE reserved for the kernel path |
| Envelope | COSE (`COSE_Encrypt0` + AEAD, HPKE-style recipient key) | CBOR-native signing/encryption; blind-courier mode |
| Hashing | SHA-256 over deterministic CBOR | Stable strict/family fingerprints |
| Outer FEC | Reed–Solomon (MVP) → RaptorQ (v1.1) | RS is simple and deterministic; RaptorQ enables mid-stream capture |
| Inner symbol | ISO QR Model 2 (byte mode) → Aztec/JAB experiments | Ubiquitous decoders; JAB is the standards-based colour path |
| Phone client | PWA (TypeScript + Rust/WASM decoder core) → native Android (Camera2) | Web is the adoption path; native is the accelerator |
| Backend | Rust (axum) + PostgreSQL; isolated symbolication workers | Same crates as producers ⇒ one canonical parser/validator |
| IPC | D-Bus `org.freedesktop.CrashCapsule1` (zbus) | Desktops/UIs never need to know the wire format |
| CI | GitHub Actions: fmt, clippy `-D warnings`, test, cross-language vectors, fuzz smoke, coverage | Interop and parser safety are the two riskiest areas |

Non-goals for v1: colour matrices, RaptorQ, in-kernel animated codec, AI triage, automatic public
issue creation.

---

## 1. Repository layout (target)

```text
crash-capsule/
├── specification/                    # normative, versioned separately from code
│   ├── crash-capsule.cddl
│   ├── visual-envelope.cddl
│   ├── privacy-registry.md + registry.toml   # machine-readable field → minimum class
│   ├── fingerprint-v1.md
│   ├── threat-model.md
│   ├── extension-registry.md
│   └── test-vectors/{canonical,malformed,fingerprint,visual}/
├── crates/
│   ├── cc-schema/         # generated field IDs, profiles, privacy floors from registry.toml
│   ├── cc-canonical/      # deterministic CBOR encode/decode + strict validation limits
│   ├── cc-redact/         # allow-list redaction, path/network/hardware scrubbers
│   ├── cc-fingerprint/    # strict + family material construction and hashing
│   ├── cc-compress/       # zstd with declared-output + hard caps (bomb-safe)
│   ├── cc-crypto/         # COSE encrypt/verify, key sets, rotation windows
│   ├── cc-capsule/        # façade: build → validate → redact → fingerprint → protect
│   ├── cc-fec/            # RS outer FEC (v1), RaptorQ behind a feature flag (v1.1)
│   ├── cc-visual/         # frame headers, CRC32C, QR rendering, frame scheduler
│   ├── cc-decode/         # camera-side: localisation, quality gate, inner decode, FEC collect
│   ├── cc-ffi/            # narrow C ABI (`libcrashcapsule.so` + header)
│   ├── crashcapsuled/     # daemon: ingest, policy, storage, D-Bus
│   ├── cc-cli/            # `crashcapsulectl`: create/inspect/preview/render/decode/submit
│   └── cc-server/         # ingress, privacy pass, symbolicate, dedupe, knownbugs, routers
├── phone/
│   ├── pwa/               # TypeScript app + WASM decoder
│   └── android/           # native Camera2 decoder (v1.2)
├── desktop/               # GTK/Qt-agnostic reporter UI (talks D-Bus only)
├── packaging/             # deb/rpm, systemd units, sysusers, tmpfiles, AppArmor/SELinux
├── testing/
│   ├── optical-corpus/    # recorded videos + ground truth
│   ├── device-matrix.md
│   └── harness/           # replay decoder against corpus, publish metrics
└── docs/                  # this plan, ADRs, user & maintainer documentation
```

Everything under `crates/` is one Cargo workspace with a shared lint/deny configuration.

---

## Phase 0 — Project foundation (prerequisite for everything)

**Goal:** a repo that can be developed in safely and reproducibly.

1. Cargo workspace skeleton, `rust-toolchain.toml` (pinned stable), `rustfmt.toml`, `clippy.toml`,
   `deny.toml` (licence + advisory gate — required before pulling in any RaptorQ/JAB code).
2. `.pre-commit-config.yaml`: `cargo fmt --check`, `cargo clippy -D warnings`, `typos`,
   `prettier` for the PWA, CDDL lint.
3. GitHub Actions: `check` (fmt/clippy), `test` (workspace + doctests), `vectors` (spec conformance),
   `fuzz-smoke` (60 s per target), `pwa` (build + vitest), `coverage`.
4. `CONTRIBUTING.md`, ADR template, `SECURITY.md` (private reporting for a project that is itself a
   security-sensitive parser), issue/PR templates.
5. `docs/architecture.md` with the layer diagram and the panic-vs-userspace split stated normatively.

**Done when:** `cargo test` and CI pass on an empty-but-wired workspace; hooks installed.

---

## Phase 1 — Specification milestone

**Goal:** the durable contribution. No transport or server work starts before this is stable.

1. **`crash-capsule.cddl`** — top-level capsule exactly as blueprinted: integer-keyed
   `component`, `system`, `event`, `[frame]`, `[evidence]`, `fingerprints`, `privacy-manifest`,
   critical-feature bitmap, optional `time-info` / `routing-hints`, open extension slot.
2. **Versioning rules** — `schema_major` (incompatible), `schema_minor` (additive),
   `profile` enum (`panic-minimal`, `visual-small`, `visual-standard`, `visual-extended`,
   `local-full`), `critical_features` bitmap with fail-closed reader semantics and
   retain-on-forward for unknown non-critical fields.
3. **Privacy registry** (`registry.toml`, generated to Markdown) — every standard field carries a
   minimum class P0–P4. Normative rule implemented in code:
   `effective_class = max(schema_minimum, producer_declared)`; producers may raise, never lower.
4. **`fingerprint-v1.md`** — exact material construction for userspace-strict, kernel-strict and
   family, including symbol normalisation (demangling, template/lambda collapsing, versioned-symbol
   suffix stripping), frame count N, module-relative PC rules, and the absolute prohibition on
   hashing VAs, PIDs, timestamps, CPU numbers or boot-local addresses.
5. **`visual-envelope.cddl`** + the `VisualFrameHeader` byte layout (magic, proto version,
   transfer ID, profile, flags, source block, ESI, symbol count/size, object length, CRC32C) with
   the explicit statement that the header is untrusted framing and all integrity lives inside COSE.
6. **`threat-model.md`** — the blueprint's threat table turned into testable mitigations, each
   linked to the test that enforces it.
7. **Test vectors** — ≥50 canonical capsules (each profile, each source kind, unicode/edge symbols),
   a malformed corpus (truncated, non-deterministic CBOR, depth bombs, duplicate keys, huge maps),
   fingerprint vectors, and visual-frame vectors. Vectors are data files consumed by both Rust and
   the TypeScript/WASM decoder tests.

**Done when:** two independent implementations (Rust encoder, TS validator harness) reproduce every
canonical byte string and every fingerprint, and reject 100% of the malformed corpus.

---

## Phase 2 — `libcrashcapsule` core

**Goal:** the pipeline `schema → classify → redact → canonicalise → fingerprint → compress →
encrypt` as a library, correct and hard against hostile input.

1. `cc-schema` — code generated from `registry.toml` at build time so registry and code cannot drift.
2. `cc-canonical` — deterministic encoder; decoder that enforces nesting depth, item counts,
   string lengths, total size, and rejects non-canonical encodings (required: canonical form is a
   fingerprint precondition).
3. `cc-redact` — allow-list first. Process metadata defaults (keep basename/build ID/package/signal/
   symbols; drop argv/env/cwd/hostname), path transforms to `$HOME/<redacted>/file.txt`, default-drop
   of IP/MAC/SSID/hostname/DNS/URLs with coarse replacements (`transport=wifi`), hardware allow-list
   (PCI/USB IDs, CPU/GPU family) with never-collect list (serials, machine UUID). Log evidence runs
   the layered scrubber chain (allow-list → field extraction → secret recognisers → path/network
   scrubbers → entropy heuristics → size cap) and stays P3-private by default.
4. `cc-fingerprint` — strict + family per spec, plus optional evidence signature.
5. `cc-compress` — zstd level 3, declared output length required, dual caps (32 KiB compressed
   visual / 256 KiB plaintext), bounded window.
6. `cc-crypto` — COSE `Encrypt0` to a triage-service public key, key set with overlapping rotation
   windows, key IDs shipped by the distro package; verification path for the server.
7. `cc-capsule` — façade with the **evidence budget algorithm**: when a capsule exceeds its profile
   limit, drop evidence in ascending priority order while guaranteeing event + fingerprints +
   privacy manifest survive; report what was dropped to the UI.
8. `cc-ffi` — narrow C ABI + generated header, for future ABRT/desktop consumers.

**Testing:** property tests (redaction never emits a dropped-class field; canonical round-trip),
`cargo-fuzz` targets for the decoder/decompressor/redactor, and a "no P3/P4 in a visual profile"
invariant test that runs over every canonical vector.

**Done when:** the same synthetic crash yields an identical strict fingerprint across differing boot
IDs, PIDs, ASLR layouts and timestamps (>99.9% over a randomised harness), and fuzzers run clean.

---

## Phase 3 — Linux ingestion (`crashcapsuled`)

**Goal:** real crashes on a real distro become capsules.

1. **Daemon skeleton** — socket-activated systemd service, dedicated system user, hardened unit
   (`ProtectSystem=strict`, `NoNewPrivileges`, `SystemCallFilter`), on-disk store at
   `/var/lib/crashcapsule` with per-incident directories, encrypted at rest, 14-day default retention
   for unsubmitted incidents.
2. **`IncidentSource` trait** and adapters:
   - **systemd-coredump adapter** — sits *after* `systemd-coredump` (never replaces
     `kernel.core_pattern`): reads journal `COREDUMP_*` metadata and the extracted backtrace,
     references (does not embed) `/var/lib/systemd/coredump/...`, records an artifact hash only.
   - **pstore adapter** — boot-time unit: inspect `/sys/fs/pstore`, discover `dmesg-*` records, copy
     to protected staging, parse oops/panic metadata (class, taint, call trace, modules), build and
     **durably commit** the capsule, and only then delete the consumed pstore record.
   - **manual/CLI source** — `crashcapsulectl create` from a JSON/CBOR description, for testing and
     application SDK use.
   - (later) systemd service-failure adapter, ABRT/libreport adapter.
3. **Policy engine** — profile selection, consent state machine, transport preferences, per-source
   caps and rate limits.
4. **D-Bus API** `org.freedesktop.CrashCapsule1`: `ReportIncident(metadata_fd, evidence_fds, flags)`,
   `GetIncident`, `ListIncidents`, `RequestVisualTransfer(id, profile)`, `Consent(id, policy)`,
   `Delete(id)`; polkit rules so a desktop session can only touch its own incidents.
5. **`crashcapsulectl`** — create, list, `inspect --explain-privacy` (the exact category preview the
   UI shows), `render`, `decode`, `submit`, `purge`.

**Done when:** on a test VM, a deliberately crashed process and a forced kernel panic (`sysrq-c`
with ramoops configured) both produce validated capsules end-to-end, with the panic capsule
surviving reboot and the pstore record consumed only after durable commit.

---

## Phase 4 — Static QR + panic-minimal profile

1. `cc-visual` QR renderer (byte mode, ECC level selected per profile) producing PNG/SVG/framebuffer
   output.
2. `panic-minimal` producer: kernel release/build identity, architecture, oops/panic class, taint,
   compact normalised top stack, module identities, protocol marker — target 0.5–1.5 KiB, hard
   2.5 KiB, no kmsg by default (expert/distro opt-in flag only).
3. Bootstrap QR mode encoding only `https://<configured-origin>/scan?v=1` plus a profile hint;
   decoders accept **only configured origins**, and dynamic payloads may never open URLs.
4. Offline verification tool: render → photograph/synthesise → decode → byte-compare.

**Done when:** panic-minimal capsules round-trip through a phone camera and a commodity scanner app
(bootstrap mode), within the size budget.

---

## Phase 5 — Dynamic monochrome optical transport (optical MVP)

1. **Frame format** — `VisualFrameHeader` + payload symbol + CRC32C; source symbol size tuned to the
   chosen QR version; transfer ID and epoch marker for multi-transfer disambiguation.
2. **Outer FEC (RS)** — `cc-fec` RS(n,k) across frames, treating whole frames as erasures;
   configurable redundancy; sender loops the source+repair sequence indefinitely so there is no
   "final frame" the user must catch.
3. **Sender/scheduler** — 10 logical symbols/s baseline, 15/s performance mode; vsync-aligned hold
   intervals; geometry target ~70–90 modules occupying most of the panel with several display pixels
   per module; on-screen progress affordance and a static-QR accessibility fallback (no rapid
   large-luminance changes; accessibility review is a gate, not a nicety).
4. **Receiver core (`cc-decode`, compiled to WASM)** — display/finder localisation, homography,
   rolling-shutter/transition/blur quality rejection, black-white level estimation, module sampling
   with confidence values, inner decode, CRC gate, FEC collector, then COSE verify → bounded
   decompress → canonical parse.
5. **Profile negotiation** — `CCV-1-MONO-SLOW` / `CCV-1-MONO-FAST` advertised in frame headers, with
   automatic fallback when the frame-rejection rate rises.
6. **PWA** — camera permission flow, live capture-progress UI, the privacy preview rendered from the
   capsule's own manifest (categories included/excluded), offline queue (store ciphertext, upload
   later), submit, and result display. Blind-courier by default: the phone holds only ciphertext;
   local-decode is an explicit opt-in mode.

**Optical test lab** (built alongside, not after): device matrix across 60/120 Hz LCD/OLED, brightness
levels, 30/60 fps cameras, distance, off-axis angle, motion, HiDPI/scaling, deliberate frame loss.
Published corpus (video + ground truth + metadata) and a replay harness computing Frame Decode Rate,
**Useful Goodput** (capsule bits ÷ time from first usable frame to verified reconstruction),
time-to-first-lock, p50/p95 capture time, fallback frequency, false-frame acceptance, CPU/battery.

**Done when:** 8 KiB capsule capture succeeds >95% across the supported matrix with p95 < 20 s, and
measured goodput lands in the 5–20 kbit/s target band.

---

## Phase 6 — Triage backend

1. **Ingress** — bounded-size encrypted upload endpoint, decrypt, schema-validate, reject anything
   non-canonical; anti-abuse quotas with the shortest viable retention for network metadata.
2. **Server privacy pass** — recompute minimum classes from the registry, re-run structured
   redaction, reject policy-prohibited fields, persist a sanitised working representation; raw
   protected material only where consent/retention policy allows (30-day default).
3. **Symbolication workers** — isolated (no network, CPU/memory/time quota, seccomp), build-ID-driven
   lookup against distro debuginfod; unsymbolicated stacks flagged as low evidence quality.
4. **Dedupe** — strict fingerprint → automatic occurrence cluster; family fingerprint → candidate
   cluster; fuzzy similarity (weighted Jaccard / MinHash over normalised frame sequences) is
   **advisory only** and can never auto-merge.
5. **Data model** — `CrashCluster` per the blueprint plus the **version incidence matrix** view that
   surfaces regressions (signature × version occurrence counts).
6. **Known-bug lookup before anything else** — answer "have developers already seen this?" and return
   remediation ("fixed in X.Y.Z, occurrence counted, no new report created") to the user.
7. **Security gate** — classifier + mandatory private queue; no automatic public publication of
   anything security-sensitive, ever.
8. **Routing** — `ReportDestination` trait with Bugzilla/GitLab/GitHub/mailing-list adapters, a
   per-project opt-in policy file (`accept`, `privacy.max_public_class`, `dedupe`, `routing`,
   `auto_file` thresholds, `attachments`), kernel routing via normalised top frame → source file →
   `MAINTAINERS`/`get_maintainer.pl`. v1 ships **manual approval only**; automated filing is v2 and
   maintainer-opt-in.
9. **Generated reports contain derived material only** — title, environment, signature, representative
   stack, aggregate observations, authorised maintainer link. Never raw journal, env, argv, core dump,
   unredacted kmsg or network metadata. Enforced by a test over the report renderer.

**Done when:** 12,000 identical submissions produce one cluster, one prepared report and 12,000
counted occurrences; and no fixture with a P2+ field can be rendered into a public report.

---

## Phase 7 — Desktop experience & packaging

1. Reporter UI (D-Bus client only): the blueprint's dialog — plain-language cause, "Report using this
   computer" / "Scan with phone" / "See information being shared" / "Don't report", plus the offline
   scan screen with live capture progress and the included/excluded category list rendered from the
   capsule manifest **before** encryption.
2. Packages: `crashcapsule-libs`, `-daemon`, `-pstore`, `-systemd`, `-render`, optional `-abrt`,
   `-desktop-gnome`, `-desktop-kde`, `-symbols`; systemd units, sysusers/tmpfiles, AppArmor/SELinux
   policy; one distro prototype first (Fedora or Ubuntu), then the second.
3. Documentation: user-facing privacy notice, maintainer onboarding guide, distro integration guide.

---

## Phase 8 — v1.1 / v1.2 / v2

- **v1.1** — RaptorQ outer FEC behind the same `cc-fec` interface (licence/security review first);
  Aztec inner-symbol trials; improved symbolication.
- **v1.2** — four-colour calibrated transport with per-frame reference patches (accepted only if
  end-to-end goodput improves on the *same* device corpus, not merely nominal bits/module); native
  Android Camera2 decoder with AE/AWB locking.
- **v2** — maintainer opt-in automated routing, backend federation (project-specific endpoints),
  kernel `panic-minimal` interoperability with the DRM panic path and the pstore hand-off.
- **Eight-colour** stays research-only.

---

## Cross-cutting workstreams (run continuously)

| Workstream | Practice |
|---|---|
| Security | Fuzz every parser in CI; parser sandboxing; `cargo deny`; external audit before the pilot |
| Privacy | Invariant tests per profile; a "privacy diff" review gate on any registry change |
| Interop | Cross-language vector tests in CI; the spec repo directory is the source of truth |
| Performance | Optical corpus replay on every `cc-decode` change; regression thresholds enforced |
| Accessibility | Static fallback always available; luminance-change limits; review before any animated default |
| Docs | ADR per significant decision; spec changes require vector updates in the same PR |

---

## Risk register → concrete mitigations

| Risk | Mitigation baked into the plan |
|---|---|
| Privacy leakage from free-form logs | Allow-list first, P3 default-deny, dual client/server redaction, invariant tests |
| Maintainer spam | Dedupe and known-bug lookup precede routing; manual approval in v1; project opt-in |
| False dedupe | Strict/family separation; fuzzy advisory-only; zero-false-merge acceptance metric |
| Kernel panic complexity | Static minimal profile only; nothing animated in panic context |
| Colour interop | Monochrome baseline must hit its targets before colour work starts |
| Rolling shutter / refresh aliasing | Long logical holds, quality rejection, outer FEC over whole-frame erasures |
| Payload creep | Hard profile limits + priority-ordered evidence dropping in `cc-capsule` |
| Fountain complexity | RS MVP, RaptorQ deferred behind a stable trait |
| Symbol availability | Build IDs everywhere; debuginfod workers; evidence-quality scoring |
| Backend centralisation | Open server implementation, federation-ready routing, project endpoints |

---

## Acceptance metrics for stable v1

| Metric | Target |
|---|---|
| 8 KiB optical capture success across supported matrix | >95% |
| p95 8 KiB capture time, baseline conditions | <20 s |
| Intentional P3/P4 fields in default visual capsules | 0 |
| Strict-fingerprint reproducibility for deterministic crashes | >99.9% |
| Verified false strict-dedupe merges | 0 |
| Public issues containing prohibited raw fields | 0 |
| Component/routing prediction accuracy after pilot | >90% |
| Useful-report conversion (accepted/matched/acted upon ÷ submitted) | primary KPI, measured upward |

---

## Sequencing and parallelism

Strict ordering: **Phase 0 → Phase 1 → Phase 2** (nothing downstream is meaningful before the schema
and core are frozen). After Phase 2, three tracks run in parallel and only rejoin for end-to-end
tests:

```text
Phase 2 (core)
   ├── Track A: Phase 3 ingestion → Phase 4 static QR → Phase 7 desktop/packaging
   ├── Track B: Phase 5 optical transport (sender + WASM decoder + PWA + optical lab)
   └── Track C: Phase 6 backend (ingress → privacy → dedupe → known-bug → routing)
```

Each phase lands as its own reviewable PR series against `main`, with the spec and its test vectors
always updated in the same PR as the code that implements them.
