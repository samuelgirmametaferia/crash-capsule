//! The canonical, malformed and fingerprint cases that make up the published corpus.
//!
//! Cases are *constructed in code and written to disk* so that the committed vectors can be
//! diffed in review: a change to the encoder that alters a single byte shows up as a change to
//! the corpus in the same pull request.

use cc_canonical::Value;
use cc_capsule::{
    Capsule, Component, Event, Evidence, Frame, Hardware, PrivacyManifest, RoutingHints, System,
    TimeInfo,
};

/// A named canonical capsule vector.
#[derive(Debug, Clone)]
pub struct CanonicalCase {
    /// File stem of the vector.
    pub name: String,
    /// What the vector is for.
    pub note: &'static str,
    /// The capsule itself.
    pub capsule: Capsule,
}

/// A named malformed input that every conforming decoder must reject.
#[derive(Debug, Clone)]
pub struct MalformedCase {
    /// File stem of the vector.
    pub name: String,
    /// Why it must be rejected.
    pub note: &'static str,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// A named fingerprint case with its expected hashes.
#[derive(Debug, Clone)]
pub struct FingerprintCase {
    /// Case name.
    pub name: String,
    /// Deterministic CBOR of the material that gets hashed.
    pub material: Vec<u8>,
    /// The resulting fingerprint.
    pub fingerprint: [u8; 32],
}

fn build_id(seed: u8) -> Vec<u8> {
    vec![seed; 20]
}

fn frame(symbol: &str, module: &str, offset: u64, seed: u8) -> Frame {
    Frame {
        build_id: Some(build_id(seed)),
        symbol: Some(symbol.to_owned()),
        offset: Some(offset),
        module: Some(module.to_owned()),
    }
}

fn manifest(max_class: u8) -> PrivacyManifest {
    PrivacyManifest {
        max_class,
        included: vec![0, 1, 2, 3, 4],
        excluded: vec![6, 7, 8, 9, 10, 11, 12],
        redactions: 0,
        dropped_evidence: 0,
    }
}

fn finish(mut capsule: Capsule) -> Capsule {
    capsule.recompute_fingerprints();
    capsule.privacy.max_class = capsule.effective_max_class().id();
    capsule
}

/// A userspace crash in a packaged application.
fn userspace_crash() -> Capsule {
    finish(Capsule {
        profile: 2,
        capsule_id: [0x11; 16],
        source_kind: 3,
        severity: 4,
        component: Component {
            kind: 2,
            package: Some("firefox".into()),
            version: Some("140.0.1".into()),
            build_id: Some(build_id(0xa1)),
            executable: Some("firefox".into()),
            subsystem: Some("gfx".into()),
            ..Component::default()
        },
        system: System {
            architecture: "x86_64".into(),
            distro_family: Some("ubuntu".into()),
            distro_release: Some("24.04".into()),
            kernel_release: Some("6.11.0-19-generic".into()),
            kernel_build_id: Some(build_id(0xbe)),
            taint: Some(0),
            hardware: Some(Hardware {
                cpu_family: Some("AMD Zen 4".into()),
                gpu_class: Some("AMD Radeon 780M".into()),
                pci_ids: vec!["1002:15bf".into()],
                firmware_version: None,
            }),
        },
        event: Event {
            failure_class: 1,
            signal: Some(11),
            reason: Some("null-dereference".into()),
            sequence: Some(1),
        },
        frames: vec![
            frame(
                "mozilla::gfx::DrawTargetSkia::Fill",
                "libxul.so",
                0x2a,
                0xa1,
            ),
            frame(
                "mozilla::layers::PaintThread::Run",
                "libxul.so",
                0x140,
                0xa1,
            ),
            frame("__libc_start_call_main", "libc.so.6", 0x80, 0xc1),
        ],
        evidence: vec![Evidence {
            kind: 1,
            declared_class: 1,
            priority: 5,
            value: Value::Array(vec![Value::text("libxul.so"), Value::text("libc.so.6")]),
            source_hash: None,
        }],
        privacy: manifest(1),
        time_info: Some(TimeInfo {
            uptime_bucket: Some(3),
            day: Some(20_400),
        }),
        routing_hints: Some(RoutingHints {
            subsystem: Some("gfx".into()),
            project: Some("mozilla/firefox".into()),
        }),
        ..Capsule::default()
    })
}

/// A kernel oops attributed to a module.
fn kernel_oops() -> Capsule {
    finish(Capsule {
        profile: 2,
        capsule_id: [0x22; 16],
        source_kind: 2,
        severity: 4,
        component: Component {
            kind: 1,
            module: Some("amdgpu".into()),
            subsystem: Some("drm".into()),
            ..Component::default()
        },
        system: System {
            architecture: "x86_64".into(),
            distro_family: Some("fedora".into()),
            distro_release: Some("42".into()),
            kernel_release: Some("6.14.3-200.fc42.x86_64".into()),
            kernel_build_id: Some(build_id(0xd0)),
            taint: Some(0x200),
            hardware: Some(Hardware {
                cpu_family: Some("Intel Raptor Lake".into()),
                gpu_class: Some("AMD Navi 33".into()),
                pci_ids: vec!["1002:7480".into()],
                firmware_version: None,
            }),
        },
        event: Event {
            failure_class: 1,
            signal: None,
            reason: Some("oops-null-deref".into()),
            sequence: Some(1),
        },
        frames: vec![
            frame("amdgpu_job_submit", "amdgpu", 0x1f, 0xd1),
            frame("drm_sched_entity_push_job", "gpu_sched", 0x84, 0xd2),
            frame("drm_ioctl", "drm", 0x2c0, 0xd3),
        ],
        evidence: vec![Evidence {
            kind: 0,
            declared_class: 1,
            priority: 7,
            value: Value::text("BUG: kernel NULL pointer dereference, address: <addr>"),
            source_hash: None,
        }],
        privacy: manifest(1),
        ..Capsule::default()
    })
}

/// The minimal capsule a panic-context producer can emit.
fn panic_minimal() -> Capsule {
    finish(Capsule {
        profile: 0,
        capsule_id: [0x33; 16],
        source_kind: 1,
        severity: 4,
        component: Component {
            kind: 0,
            module: Some("i915".into()),
            ..Component::default()
        },
        system: System {
            architecture: "x86_64".into(),
            kernel_release: Some("6.14.3".into()),
            kernel_build_id: Some(build_id(0xe1)),
            taint: Some(0),
            ..System::default()
        },
        event: Event {
            failure_class: 2,
            reason: Some("panic".into()),
            ..Event::default()
        },
        frames: vec![
            frame("intel_atomic_commit_tail", "i915", 0x310, 0xe1),
            frame("commit_tail", "drm_kms_helper", 0x5c, 0xe2),
        ],
        evidence: Vec::new(),
        privacy: PrivacyManifest {
            max_class: 1,
            included: vec![1, 2, 5],
            excluded: vec![6, 7, 8, 9, 10, 11, 12],
            redactions: 0,
            dropped_evidence: 0,
        },
        ..Capsule::default()
    })
}

/// A failed systemd service.
fn service_failure() -> Capsule {
    finish(Capsule {
        profile: 1,
        capsule_id: [0x44; 16],
        source_kind: 4,
        severity: 3,
        component: Component {
            kind: 4,
            package: Some("systemd".into()),
            version: Some("255.4".into()),
            executable: Some("systemd-resolved".into()),
            subsystem: Some("network".into()),
            ..Component::default()
        },
        system: System {
            architecture: "aarch64".into(),
            distro_family: Some("debian".into()),
            distro_release: Some("13".into()),
            kernel_release: Some("6.12.9-arm64".into()),
            ..System::default()
        },
        event: Event {
            failure_class: 4,
            signal: Some(6),
            reason: Some("service-abort".into()),
            sequence: Some(4),
        },
        frames: vec![frame(
            "manager_dispatch_sigchld",
            "systemd-resolved",
            0x91,
            0xf1,
        )],
        evidence: vec![Evidence {
            kind: 2,
            declared_class: 1,
            priority: 4,
            value: Value::Map(vec![
                (Value::text("transport"), Value::text("wifi")),
                (Value::text("address_family"), Value::text("ipv6")),
            ]),
            source_hash: None,
        }],
        privacy: manifest(1),
        ..Capsule::default()
    })
}

/// Returns the canonical corpus.
///
/// The base cases cover each source kind and profile; the generated variations then exercise the
/// encoder's edge cases (empty collections, maximum-width integers, unicode, long symbols,
/// optional maps present and absent) so that a cross-language implementation has something to
/// disagree with us about.
pub fn canonical_cases() -> Vec<CanonicalCase> {
    let mut cases = vec![
        CanonicalCase {
            name: "userspace-crash-standard".to_owned(),
            note: "packaged application SIGSEGV, visual-standard profile",
            capsule: userspace_crash(),
        },
        CanonicalCase {
            name: "kernel-oops-module".to_owned(),
            note: "kernel oops attributed to a module, tainted kernel",
            capsule: kernel_oops(),
        },
        CanonicalCase {
            name: "panic-minimal".to_owned(),
            note: "smallest panic-context capsule, no evidence",
            capsule: panic_minimal(),
        },
        CanonicalCase {
            name: "service-failure-small".to_owned(),
            note: "systemd service abort, visual-small profile, aarch64",
            capsule: service_failure(),
        },
    ];

    // Optional-field coverage.
    let mut no_optionals = userspace_crash();
    no_optionals.time_info = None;
    no_optionals.routing_hints = None;
    no_optionals.system.hardware = None;
    no_optionals.evidence.clear();
    cases.push(CanonicalCase {
        name: "userspace-crash-no-optional-maps".to_owned(),
        note: "every optional map absent",
        capsule: finish(no_optionals),
    });

    let mut no_frames = panic_minimal();
    no_frames.frames.clear();
    cases.push(CanonicalCase {
        name: "panic-minimal-no-frames".to_owned(),
        note: "unwinding failed; empty frame array must still encode",
        capsule: finish(no_frames),
    });

    // Integer-width coverage: each argument width must appear somewhere in the corpus.
    for (name, value) in [
        ("uint-tiny", 23u64),
        ("uint-u8", 24),
        ("uint-u16", 0x0100),
        ("uint-u32", 0x0001_0000),
        ("uint-u64", 0x0000_0001_0000_0000),
        ("uint-max", u64::MAX),
    ] {
        let mut capsule = userspace_crash();
        capsule.event.sequence = Some(value);
        if let Some(first) = capsule.frames.first_mut() {
            first.offset = Some(value);
        }
        cases.push(CanonicalCase {
            name: format!("encoding-{name}"),
            note: "argument width coverage",
            capsule: finish(capsule),
        });
    }

    for (name, signal) in [
        ("signal-negative-small", -1i64),
        ("signal-negative-wide", -1000),
        ("signal-zero", 0),
    ] {
        let mut capsule = service_failure();
        capsule.event.signal = Some(signal);
        cases.push(CanonicalCase {
            name: format!("encoding-{name}"),
            note: "negative integer coverage",
            capsule: finish(capsule),
        });
    }

    // Symbol normalisation coverage: each of these must fingerprint like its plain form.
    for (index, symbol) in [
        "memcpy@@GLIBC_2.14",
        "foo_submit+0x1f/0x40",
        "do_thing.constprop.0",
        "ns::render<Pixel>(int, int)",
        "core::fmt::write::h0123456789abcdef",
        "_ZN4core3fmt5write17h9f0c1d2e3a4b5c6dE",
        "队列处理",
        "symbol_with_a_very_long_name_that_exercises_string_length_encoding_past_the_twenty_four_byte_boundary",
    ]
    .into_iter()
    .enumerate()
    {
        let mut capsule = userspace_crash();
        if let Some(first) = capsule.frames.first_mut() {
            first.symbol = Some(symbol.to_owned());
        }
        cases.push(CanonicalCase {
            name: format!("symbol-{index:02}"),
            note: "symbol normalisation and text encoding coverage",
            capsule: finish(capsule),
        });
    }

    // Profile coverage, including the classes each profile is allowed to carry.
    for spec in cc_schema::PROFILES {
        let mut capsule = userspace_crash();
        capsule.profile = spec.id;
        capsule
            .evidence
            .retain(|item| item.effective_class() <= spec.max_privacy_class());
        cases.push(CanonicalCase {
            name: format!("profile-{}", spec.name),
            note: "profile coverage",
            capsule: finish(capsule),
        });
    }

    // Evidence coverage: one vector per registered evidence kind, on a profile that permits it.
    for (kind, name, floor) in cc_schema::EVIDENCE_KINDS {
        let mut capsule = userspace_crash();
        capsule.profile = 4; // local-full permits up to P3
        let item = Evidence {
            kind: *kind,
            declared_class: *floor,
            priority: 3,
            value: Value::text(format!("{name} payload")),
            source_hash: Some(vec![0x5e; 32]),
        };
        if item.effective_class() <= cc_schema::PrivacyClass::P3 {
            capsule.evidence = vec![item];
            cases.push(CanonicalCase {
                name: format!("evidence-{name}"),
                note: "evidence kind coverage",
                capsule: finish(capsule),
            });
        }
    }

    // Source-kind and failure-class coverage.
    for (id, name) in cc_schema::SOURCE_KINDS {
        let mut capsule = userspace_crash();
        capsule.source_kind = *id;
        cases.push(CanonicalCase {
            name: format!("source-kind-{name}"),
            note: "source kind coverage",
            capsule: finish(capsule),
        });
    }

    for (id, name) in cc_schema::FAILURE_CLASSES {
        let mut capsule = kernel_oops();
        capsule.event.failure_class = *id;
        cases.push(CanonicalCase {
            name: format!("failure-class-{name}"),
            note: "failure class coverage",
            capsule: finish(capsule),
        });
    }

    // Component-kind and severity coverage.
    for kind in 0..=4u64 {
        let mut capsule = userspace_crash();
        capsule.component.kind = kind;
        cases.push(CanonicalCase {
            name: format!("component-kind-{kind}"),
            note: "component kind coverage",
            capsule: finish(capsule),
        });
    }

    for severity in 0..=5u64 {
        let mut capsule = service_failure();
        capsule.severity = severity;
        cases.push(CanonicalCase {
            name: format!("severity-{severity}"),
            note: "severity coverage",
            capsule: finish(capsule),
        });
    }

    // Deep-but-legal evidence nesting, to pin the decoder's depth accounting.
    let mut nested = userspace_crash();
    nested.profile = 4;
    let mut value = Value::text("leaf");
    for _ in 0..8 {
        value = Value::Array(vec![value]);
    }
    nested.evidence = vec![Evidence {
        kind: 2,
        declared_class: 1,
        priority: 2,
        value,
        source_hash: None,
    }];
    cases.push(CanonicalCase {
        name: "evidence-nested-structure".to_owned(),
        note: "legal nesting close to the depth limit",
        capsule: finish(nested),
    });

    cases
}

/// Returns the malformed corpus. Every entry must be rejected by a conforming decoder.
pub fn malformed_cases() -> Vec<MalformedCase> {
    let valid = canonical_cases()
        .first()
        .map(|case| case.capsule.encode())
        .unwrap_or_default();

    let mut cases = vec![
        MalformedCase {
            name: "empty".to_owned(),
            note: "no input at all",
            bytes: Vec::new(),
        },
        MalformedCase {
            name: "truncated-capsule".to_owned(),
            note: "a valid capsule cut in half",
            bytes: valid.get(..valid.len() / 2).unwrap_or_default().to_vec(),
        },
        MalformedCase {
            name: "trailing-bytes".to_owned(),
            note: "a valid capsule with junk appended",
            bytes: {
                let mut bytes = valid.clone();
                bytes.push(0x00);
                bytes
            },
        },
        MalformedCase {
            name: "non-canonical-integer".to_owned(),
            note: "1 encoded in a two-byte argument",
            bytes: vec![0x18, 0x01],
        },
        MalformedCase {
            name: "indefinite-length-bstr".to_owned(),
            note: "indefinite lengths are not deterministic",
            bytes: vec![0x5f, 0x41, 0x01, 0xff],
        },
        MalformedCase {
            name: "indefinite-length-map".to_owned(),
            note: "indefinite lengths are not deterministic",
            bytes: vec![0xbf, 0x00, 0x00, 0xff],
        },
        MalformedCase {
            name: "tagged-value".to_owned(),
            note: "tags are outside the supported subset",
            bytes: vec![0xc0, 0x00],
        },
        MalformedCase {
            name: "float".to_owned(),
            note: "floats are outside the supported subset",
            bytes: vec![0xfa, 0x47, 0xc3, 0x50, 0x00],
        },
        MalformedCase {
            name: "unsorted-map-keys".to_owned(),
            note: "canonical order is bytewise on encoded keys",
            bytes: vec![0xa2, 0x0a, 0xf6, 0x02, 0xf6],
        },
        MalformedCase {
            name: "duplicate-map-key".to_owned(),
            note: "duplicate keys make decoding ambiguous",
            bytes: vec![0xa2, 0x02, 0xf6, 0x02, 0xf6],
        },
        MalformedCase {
            name: "invalid-utf8".to_owned(),
            note: "text strings must be valid UTF-8",
            bytes: vec![0x62, 0xff, 0xfe],
        },
        MalformedCase {
            name: "huge-declared-string".to_owned(),
            note: "declares a 4 GiB byte string in five bytes",
            bytes: vec![0x5a, 0xff, 0xff, 0xff, 0xff],
        },
        MalformedCase {
            name: "reserved-additional-info".to_owned(),
            note: "additional information 28 is reserved",
            bytes: vec![0x1c],
        },
    ];

    // Depth bomb: nested arrays past the decoder limit.
    let mut depth_bomb = vec![0x81; 64];
    depth_bomb.push(0xf6);
    cases.push(MalformedCase {
        name: "depth-bomb".to_owned(),
        note: "64 nested arrays exceeds the depth limit",
        bytes: depth_bomb,
    });

    cases
}

/// Returns the fingerprint corpus.
pub fn fingerprint_cases() -> Vec<FingerprintCase> {
    let frames = vec![
        cc_fingerprint::Frame {
            build_id: Some(build_id(0xa1)),
            module: Some("libxul.so".into()),
            symbol: Some("mozilla::gfx::DrawTargetSkia::Fill".into()),
            offset: Some(0x2a),
        },
        cc_fingerprint::Frame {
            build_id: Some(build_id(0xa1)),
            module: Some("libxul.so".into()),
            symbol: Some("mozilla::layers::PaintThread::Run".into()),
            offset: Some(0x140),
        },
    ];

    let userspace = cc_fingerprint::UserspaceStrict {
        source_kind: 3,
        failure_class: 1,
        component: "firefox",
        build_id: &build_id(0xa1),
        signal: 11,
        frames: &frames,
    };
    let kernel = cc_fingerprint::KernelStrict {
        failure_class: 1,
        kernel_build_id: &build_id(0xd0),
        architecture: "x86_64",
        module: Some("amdgpu"),
        frames: &frames,
        taint: 0x200,
    };
    let family = cc_fingerprint::Family {
        source_kind: 3,
        component: "firefox",
        failure_class: 1,
        frames: &frames,
    };

    vec![
        FingerprintCase {
            name: "userspace-strict".to_owned(),
            material: cc_canonical::encode(&cc_fingerprint::userspace_strict_material(&userspace)),
            fingerprint: cc_fingerprint::userspace_strict(&userspace),
        },
        FingerprintCase {
            name: "kernel-strict".to_owned(),
            material: cc_canonical::encode(&cc_fingerprint::kernel_strict_material(&kernel)),
            fingerprint: cc_fingerprint::kernel_strict(&kernel),
        },
        FingerprintCase {
            name: "family".to_owned(),
            material: cc_canonical::encode(&cc_fingerprint::family_material(&family)),
            fingerprint: cc_fingerprint::family(&family),
        },
    ]
}
