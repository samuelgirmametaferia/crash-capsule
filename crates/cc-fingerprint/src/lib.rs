//! Crash Capsule fingerprints, version `ccfp/1`.
//!
//! Two hashes answer two different questions:
//!
//! * the **strict** fingerprint answers "is this the same crash in the same build?";
//! * the **family** fingerprint answers "is this probably the same underlying bug across
//!   builds?" by discarding build-local precision.
//!
//! Both are `SHA-256` over deterministic CBOR of an explicitly ordered material array, so any
//! conforming implementation derives the same bytes.
//!
//! Boot-local values are never hashed: absolute virtual addresses, ASLR/KASLR bases, PIDs,
//! timestamps and CPU numbers are excluded by construction — [`Frame`] can only express a
//! module-relative offset.

#![deny(missing_docs)]

use cc_canonical::{encode, Value};
use sha2::{Digest, Sha256};

/// Domain separation prefix for userspace strict material.
pub const DOMAIN_STRICT: &str = "ccfp/1/strict";
/// Domain separation prefix for kernel strict material.
pub const DOMAIN_KERNEL_STRICT: &str = "ccfp/1/kernel-strict";
/// Domain separation prefix for family material.
pub const DOMAIN_FAMILY: &str = "ccfp/1/family";

/// Number of leading frames that contribute to a fingerprint.
///
/// Deeper frames are dominated by generic entry points and add noise rather than identity.
pub const FINGERPRINT_FRAMES: usize = 5;

/// A stack frame reduced to the parts that are stable across boots and builds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    /// Build ID of the object owning the frame, when known.
    pub build_id: Option<Vec<u8>>,
    /// Module or object identity, e.g. `libc.so.6` or `amdgpu`.
    pub module: Option<String>,
    /// Symbol name; normalise with [`normalise_symbol`] before use.
    pub symbol: Option<String>,
    /// Offset relative to the module or function, never an absolute address.
    pub offset: Option<u64>,
}

/// Inputs to the userspace strict fingerprint.
#[derive(Debug, Clone, Default)]
pub struct UserspaceStrict<'a> {
    /// Producer source kind.
    pub source_kind: u64,
    /// Failure class.
    pub failure_class: u64,
    /// Executable or package namespace.
    pub component: &'a str,
    /// Build ID of the failing executable.
    pub build_id: &'a [u8],
    /// Signal number or exception code.
    pub signal: i64,
    /// Frames, most recent first.
    pub frames: &'a [Frame],
}

/// Inputs to the kernel strict fingerprint.
#[derive(Debug, Clone, Default)]
pub struct KernelStrict<'a> {
    /// Panic or oops class.
    pub failure_class: u64,
    /// Kernel build ID.
    pub kernel_build_id: &'a [u8],
    /// Machine architecture.
    pub architecture: &'a str,
    /// Responsible module, when the producer could attribute one.
    pub module: Option<&'a str>,
    /// Frames, most recent first.
    pub frames: &'a [Frame],
    /// Taint bits considered semantically relevant to the failure.
    pub taint: u64,
}

/// Inputs to the family fingerprint.
#[derive(Debug, Clone, Default)]
pub struct Family<'a> {
    /// Producer source kind.
    pub source_kind: u64,
    /// Component namespace, without version or build identity.
    pub component: &'a str,
    /// Failure class.
    pub failure_class: u64,
    /// Frames, most recent first.
    pub frames: &'a [Frame],
}

/// Normalises a symbol name so that the same function hashes identically across builds.
///
/// The transformations are deliberately conservative and order-dependent:
///
/// 1. strip a versioned-symbol suffix (`memcpy@@GLIBC_2.14` → `memcpy`);
/// 2. strip a trailing module offset (`foo_submit+0x1f/0x40` → `foo_submit`);
/// 3. strip compiler-generated local suffixes (`foo.cold`, `foo.constprop.0`, `foo.isra.7`);
/// 4. collapse any template or argument list (`ns::f<T>(int)` → `ns::f`);
/// 5. strip a trailing hash-like disambiguator (`_ZN3foo17h9f0c...E` style `::h<hex>`).
#[must_use]
pub fn normalise_symbol(symbol: &str) -> String {
    let mut s = symbol.trim();

    if let Some((head, _)) = s.split_once('@') {
        s = head;
    }
    if let Some((head, _)) = s.split_once('+') {
        s = head;
    }

    // Drop everything from the first `(` or `<`, which starts an argument or template list.
    let cut = s.find(['(', '<']).unwrap_or(s.len());
    let mut out = s.get(..cut).unwrap_or(s).trim().to_owned();

    for suffix in [".cold", ".part", ".isra", ".constprop", ".localalias"] {
        if let Some(index) = out.find(suffix) {
            out.truncate(index);
        }
    }

    // Rust legacy mangling appends `::h<16 hex digits>`.
    if let Some(index) = out.rfind("::h") {
        let tail = out.get(index + 3..).unwrap_or_default();
        if tail.len() == 16 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.truncate(index);
        }
    }

    out
}

fn frame_strict(frame: &Frame) -> Value {
    Value::Array(vec![
        frame
            .build_id
            .as_ref()
            .map_or(Value::Null, |b| Value::bytes(b.clone())),
        frame
            .symbol
            .as_deref()
            .map_or(Value::Null, |s| Value::text(normalise_symbol(s))),
        frame.offset.map_or(Value::Null, Value::Unsigned),
    ])
}

fn frame_family(frame: &Frame) -> Value {
    Value::Array(vec![
        frame
            .module
            .as_deref()
            .map_or(Value::Null, |m| Value::text(m.to_owned())),
        frame
            .symbol
            .as_deref()
            .map_or(Value::Null, |s| Value::text(normalise_symbol(s))),
    ])
}

fn top_frames(frames: &[Frame], project: impl Fn(&Frame) -> Value) -> Value {
    Value::Array(
        frames
            .iter()
            .take(FINGERPRINT_FRAMES)
            .map(project)
            .collect(),
    )
}

/// Builds the userspace strict material, the exact structure that gets hashed.
#[must_use]
pub fn userspace_strict_material(input: &UserspaceStrict<'_>) -> Value {
    Value::Array(vec![
        Value::text(DOMAIN_STRICT),
        Value::Unsigned(input.source_kind),
        Value::Unsigned(input.failure_class),
        Value::text(input.component),
        Value::bytes(input.build_id),
        Value::int(input.signal),
        top_frames(input.frames, frame_strict),
    ])
}

/// Builds the kernel strict material.
#[must_use]
pub fn kernel_strict_material(input: &KernelStrict<'_>) -> Value {
    Value::Array(vec![
        Value::text(DOMAIN_KERNEL_STRICT),
        Value::Unsigned(input.failure_class),
        Value::bytes(input.kernel_build_id),
        Value::text(input.architecture),
        input
            .module
            .map_or(Value::Null, |m| Value::text(m.to_owned())),
        top_frames(input.frames, frame_strict),
        Value::Unsigned(input.taint),
    ])
}

/// Builds the family material.
#[must_use]
pub fn family_material(input: &Family<'_>) -> Value {
    Value::Array(vec![
        Value::text(DOMAIN_FAMILY),
        Value::Unsigned(input.source_kind),
        Value::text(input.component),
        Value::Unsigned(input.failure_class),
        top_frames(input.frames, frame_family),
    ])
}

/// Hashes fingerprint material: `SHA-256(deterministic_CBOR(material))`.
#[must_use]
pub fn hash_material(material: &Value) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(encode(material));
    hasher.finalize().into()
}

/// Computes the userspace strict fingerprint.
#[must_use]
pub fn userspace_strict(input: &UserspaceStrict<'_>) -> [u8; 32] {
    hash_material(&userspace_strict_material(input))
}

/// Computes the kernel strict fingerprint.
#[must_use]
pub fn kernel_strict(input: &KernelStrict<'_>) -> [u8; 32] {
    hash_material(&kernel_strict_material(input))
}

/// Computes the family fingerprint.
#[must_use]
pub fn family(input: &Family<'_>) -> [u8; 32] {
    hash_material(&family_material(input))
}

/// Formats the 128-bit human-facing signature of a fingerprint, e.g. `CCFP1-a1b2...`.
///
/// The full 256-bit value remains authoritative; this is only for display.
#[must_use]
pub fn signature(fingerprint: &[u8; 32]) -> String {
    let mut s = String::from("CCFP1-");
    for byte in fingerprint.iter().take(16) {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    fn frames() -> Vec<Frame> {
        vec![
            Frame {
                build_id: Some(vec![0xaa; 20]),
                module: Some("amdgpu".into()),
                symbol: Some("foo_submit+0x1f/0x40".into()),
                offset: Some(0x1f),
            },
            Frame {
                build_id: Some(vec![0xaa; 20]),
                module: Some("amdgpu".into()),
                symbol: Some("bar_ioctl".into()),
                offset: Some(0x84),
            },
        ]
    }

    #[test]
    fn symbol_normalisation() {
        assert_eq!(normalise_symbol("memcpy@@GLIBC_2.14"), "memcpy");
        assert_eq!(normalise_symbol("foo_submit+0x1f/0x40"), "foo_submit");
        assert_eq!(normalise_symbol("do_thing.constprop.0"), "do_thing");
        assert_eq!(
            normalise_symbol("ns::render<Pixel>(int, int)"),
            "ns::render"
        );
        assert_eq!(
            normalise_symbol("core::fmt::write::h0123456789abcdef"),
            "core::fmt::write"
        );
    }

    #[test]
    fn strict_fingerprint_is_stable_and_frame_sensitive() {
        let frames = frames();
        let base = UserspaceStrict {
            source_kind: 3,
            failure_class: 1,
            component: "firefox",
            build_id: &[0xbb; 20],
            signal: 11,
            frames: &frames,
        };
        let a = userspace_strict(&base);
        assert_eq!(a, userspace_strict(&base), "hashing must be deterministic");

        let mut swapped = frames.clone();
        swapped.swap(0, 1);
        let b = userspace_strict(&UserspaceStrict {
            frames: &swapped,
            ..base.clone()
        });
        assert_ne!(a, b, "frame order is part of the identity");
    }

    #[test]
    fn family_fingerprint_survives_a_rebuild() {
        let mut rebuilt = frames();
        for frame in &mut rebuilt {
            // A rebuild moves build IDs and offsets but keeps module and symbol.
            frame.build_id = Some(vec![0xcc; 20]);
            frame.offset = frame.offset.map(|o| o + 0x40);
        }
        let old = family(&Family {
            source_kind: 1,
            component: "kernel",
            failure_class: 1,
            frames: &frames(),
        });
        let new = family(&Family {
            source_kind: 1,
            component: "kernel",
            failure_class: 1,
            frames: &rebuilt,
        });
        assert_eq!(old, new);

        // The strict fingerprint must NOT survive it.
        let strict_old = kernel_strict(&KernelStrict {
            failure_class: 1,
            kernel_build_id: &[0x01; 20],
            architecture: "x86_64",
            module: Some("amdgpu"),
            frames: &frames(),
            taint: 0,
        });
        let strict_new = kernel_strict(&KernelStrict {
            failure_class: 1,
            kernel_build_id: &[0x02; 20],
            architecture: "x86_64",
            module: Some("amdgpu"),
            frames: &rebuilt,
            taint: 0,
        });
        assert_ne!(strict_old, strict_new);
    }

    #[test]
    fn only_the_top_frames_contribute() {
        let mut deep = frames();
        for i in 0..10 {
            deep.push(Frame {
                symbol: Some(format!("generic_entry_{i}")),
                ..Frame::default()
            });
        }
        let mut deeper = deep.clone();
        deeper.push(Frame {
            symbol: Some("irrelevant".into()),
            ..Frame::default()
        });
        let f = |frames: &[Frame]| {
            family(&Family {
                source_kind: 3,
                component: "x",
                failure_class: 1,
                frames,
            })
        };
        assert_eq!(f(&deep), f(&deeper));
    }

    #[test]
    fn signature_is_a_128_bit_prefix() {
        let fingerprint = [0xabu8; 32];
        assert_eq!(signature(&fingerprint).len(), "CCFP1-".len() + 32);
    }
}
