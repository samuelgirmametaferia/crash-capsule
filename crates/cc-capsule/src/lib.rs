//! The Crash Capsule object model: build, validate, fingerprint and budget capsules.
//!
//! This crate is the façade the producers use. It owns three rules that the rest of the system
//! depends on and that are therefore tested here rather than in each producer:
//!
//! * **Fail closed on unknown critical features.** A capsule that sets a critical bit this
//!   reader does not implement is rejected, never partially interpreted.
//! * **The registry floor wins.** An evidence item's effective class is
//!   `max(registry floor for its kind, producer declaration)`, so a buggy producer cannot
//!   publish `raw-log-text` as public.
//! * **The profile budget never sacrifices identity.** When a capsule exceeds its profile,
//!   evidence is dropped in ascending priority order; the event, the fingerprints and the
//!   privacy manifest always survive.

#![deny(missing_docs)]

mod decode;
mod model;

pub use model::{
    Capsule, Component, Event, Evidence, Fingerprints, Frame, Hardware, PrivacyManifest,
    RoutingHints, System, TimeInfo,
};

/// Critical feature bits this implementation understands.
///
/// Every bit set in a capsule's `critical_features` that is absent here causes validation to
/// fail; that is the point of the mechanism.
pub const SUPPORTED_CRITICAL_FEATURES: u64 = 0;

/// Errors produced while decoding or validating a capsule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The CBOR itself was malformed or non-canonical.
    #[error("canonical CBOR error: {0}")]
    Canonical(#[from] cc_canonical::Error),
    /// A required field was absent.
    #[error("missing required field `{field}`")]
    MissingField {
        /// Registry path of the missing field.
        field: &'static str,
    },
    /// A field had the wrong CBOR type or size.
    #[error("field `{field}` has the wrong type or size")]
    WrongType {
        /// Registry path of the offending field.
        field: &'static str,
    },
    /// The capsule was produced by an incompatible schema generation.
    #[error("unsupported schema major version {found}, this reader implements {supported}")]
    UnsupportedSchema {
        /// Version found in the capsule.
        found: u64,
        /// Version this reader implements.
        supported: u64,
    },
    /// The capsule requires a critical feature this reader does not implement.
    #[error("unknown critical feature bits 0x{bits:x}")]
    UnknownCriticalFeature {
        /// The unsupported bits.
        bits: u64,
    },
    /// The profile identifier is not in the registry.
    #[error("unknown profile {profile}")]
    UnknownProfile {
        /// The unregistered profile identifier.
        profile: u64,
    },
    /// An evidence item carries a class the profile forbids.
    #[error(
        "evidence kind {kind} is {found:?} but profile `{profile}` permits at most {allowed:?}"
    )]
    ClassAboveProfile {
        /// Offending evidence kind.
        kind: u64,
        /// Effective class of the item.
        found: cc_schema::PrivacyClass,
        /// Profile name.
        profile: &'static str,
        /// Highest class the profile permits.
        allowed: cc_schema::PrivacyClass,
    },
    /// The manifest understates the material actually present.
    #[error("privacy manifest declares {declared:?} but the capsule carries {found:?}")]
    ManifestUnderstatesClass {
        /// Class declared in the manifest.
        declared: cc_schema::PrivacyClass,
        /// Highest effective class found.
        found: cc_schema::PrivacyClass,
    },
    /// The encoded capsule exceeds its profile budget.
    #[error("capsule is {size} bytes, profile `{profile}` allows {allowed}")]
    OverBudget {
        /// Encoded size.
        size: u64,
        /// Profile name.
        profile: &'static str,
        /// Budget in bytes.
        allowed: u64,
    },
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

impl Capsule {
    /// Returns the registry entry for this capsule's profile.
    pub fn profile_spec(&self) -> Result<&'static cc_schema::ProfileSpec> {
        cc_schema::profile(self.profile).ok_or(Error::UnknownProfile {
            profile: self.profile,
        })
    }

    /// Highest effective privacy class actually present in the capsule.
    #[must_use]
    pub fn effective_max_class(&self) -> cc_schema::PrivacyClass {
        self.evidence
            .iter()
            .map(Evidence::effective_class)
            .max()
            .unwrap_or(cc_schema::PrivacyClass::P1)
    }

    /// Validates the capsule against the schema registry.
    ///
    /// Size is deliberately not checked here: the profile budget applies to the compressed
    /// payload, so [`Capsule::check_transport_size`] takes the compressed length instead.
    pub fn validate(&self) -> Result<()> {
        if self.schema_major != cc_schema::SCHEMA_MAJOR {
            return Err(Error::UnsupportedSchema {
                found: self.schema_major,
                supported: cc_schema::SCHEMA_MAJOR,
            });
        }

        let unknown = self.critical_features & !SUPPORTED_CRITICAL_FEATURES;
        if unknown != 0 {
            return Err(Error::UnknownCriticalFeature { bits: unknown });
        }

        let spec = self.profile_spec()?;
        let allowed = spec.max_privacy_class();
        for item in &self.evidence {
            let found = item.effective_class();
            if found > allowed {
                return Err(Error::ClassAboveProfile {
                    kind: item.kind,
                    found,
                    profile: spec.name,
                    allowed,
                });
            }
        }

        let declared = cc_schema::PrivacyClass::from_id(self.privacy.max_class)
            .unwrap_or(cc_schema::PrivacyClass::P0);
        let found = self.effective_max_class();
        if declared < found {
            return Err(Error::ManifestUnderstatesClass { declared, found });
        }

        Ok(())
    }

    /// Checks a compressed payload length against the profile budget.
    ///
    /// The limit applies after redaction and compression but before outer FEC.
    pub fn check_transport_size(&self, compressed_len: usize) -> Result<()> {
        let spec = self.profile_spec()?;
        let size = compressed_len as u64;
        if size > spec.max_bytes {
            return Err(Error::OverBudget {
                size,
                profile: spec.name,
                allowed: spec.max_bytes,
            });
        }
        Ok(())
    }

    /// Recomputes and stores the strict and family fingerprints.
    ///
    /// Kernel sources use the kernel strict material; everything else uses the userspace
    /// material. Fingerprint inputs are cleared from the capsule first so that the hash never
    /// depends on a previously stored fingerprint.
    pub fn recompute_fingerprints(&mut self) {
        let frames: Vec<cc_fingerprint::Frame> = self
            .frames
            .iter()
            .map(Frame::to_fingerprint_frame)
            .collect();
        let component = self
            .component
            .package
            .clone()
            .or_else(|| self.component.executable.clone())
            .or_else(|| self.component.module.clone())
            .unwrap_or_default();

        let strict = if self.source_kind == 1 || self.source_kind == 2 {
            cc_fingerprint::kernel_strict(&cc_fingerprint::KernelStrict {
                failure_class: self.event.failure_class,
                kernel_build_id: self.system.kernel_build_id.as_deref().unwrap_or_default(),
                architecture: &self.system.architecture,
                module: self.component.module.as_deref(),
                frames: &frames,
                taint: self.system.taint.unwrap_or(0),
            })
        } else {
            cc_fingerprint::userspace_strict(&cc_fingerprint::UserspaceStrict {
                source_kind: self.source_kind,
                failure_class: self.event.failure_class,
                component: &component,
                build_id: self.component.build_id.as_deref().unwrap_or_default(),
                signal: self.event.signal.unwrap_or(0),
                frames: &frames,
            })
        };

        self.fingerprints.strict = strict;
        self.fingerprints.family = cc_fingerprint::family(&cc_fingerprint::Family {
            source_kind: self.source_kind,
            component: &component,
            failure_class: self.event.failure_class,
            frames: &frames,
        });
    }

    /// Human-facing signature of the strict fingerprint.
    #[must_use]
    pub fn signature(&self) -> String {
        cc_fingerprint::signature(&self.fingerprints.strict)
    }

    /// Applies the profile budget to the evidence array.
    ///
    /// Items above the profile's maximum privacy class are dropped first, then the lowest
    /// priority items, until `measure(encoded capsule) <= limit`. The event, frames,
    /// fingerprints and privacy manifest are never dropped, so a capsule that is still over
    /// budget with no evidence left is returned as-is and rejected later by
    /// [`Capsule::check_transport_size`] — silently truncating identity would be worse than
    /// failing.
    ///
    /// `measure` is supplied by the caller because the real budget applies to the *compressed*
    /// payload, which this crate deliberately knows nothing about.
    pub fn apply_evidence_budget(&mut self, limit: u64, measure: impl Fn(&[u8]) -> u64) {
        let allowed = match self.profile_spec() {
            Ok(spec) => spec.max_privacy_class(),
            Err(_) => cc_schema::PrivacyClass::P0,
        };

        let before = self.evidence.len();
        self.evidence
            .retain(|item| item.effective_class() <= allowed);

        while measure(&self.encode()) > limit && !self.evidence.is_empty() {
            let victim = self
                .evidence
                .iter()
                .enumerate()
                .min_by_key(|(index, item)| (item.priority, *index))
                .map(|(index, _)| index);
            match victim {
                Some(index) => {
                    self.evidence.remove(index);
                }
                None => break,
            }
        }

        self.privacy.dropped_evidence += (before - self.evidence.len()) as u64;
        self.privacy.max_class = self.effective_max_class().id();
    }
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
    use cc_canonical::Value;

    fn evidence(kind: u64, declared: u8, priority: u64, size: usize) -> Evidence {
        Evidence {
            kind,
            declared_class: declared,
            priority,
            value: Value::bytes(vec![0x5a; size]),
            source_hash: None,
        }
    }

    fn capsule() -> Capsule {
        let mut capsule = Capsule {
            profile: 2,
            source_kind: 3,
            severity: 4,
            component: Component {
                kind: 3,
                package: Some("firefox".into()),
                version: Some("140.0".into()),
                build_id: Some(vec![0xab; 20]),
                executable: Some("firefox".into()),
                ..Component::default()
            },
            system: System {
                architecture: "x86_64".into(),
                distro_family: Some("ubuntu".into()),
                kernel_release: Some("6.11.0-19-generic".into()),
                ..System::default()
            },
            event: Event {
                failure_class: 1,
                signal: Some(11),
                ..Event::default()
            },
            frames: vec![Frame {
                symbol: Some("mozilla::gfx::Paint".into()),
                module: Some("libxul.so".into()),
                offset: Some(0x2a),
                build_id: Some(vec![0xab; 20]),
            }],
            privacy: PrivacyManifest {
                max_class: 1,
                included: vec![0, 1, 2],
                excluded: vec![6, 7, 9],
                redactions: 3,
                dropped_evidence: 0,
            },
            ..Capsule::default()
        };
        capsule.recompute_fingerprints();
        capsule
    }

    #[test]
    fn round_trips_through_canonical_cbor() {
        let capsule = capsule();
        let bytes = capsule.encode();
        let decoded = Capsule::decode(&bytes).expect("decodes");
        assert_eq!(decoded, capsule);
        assert_eq!(
            decoded.encode(),
            bytes,
            "re-encoding must be byte-identical"
        );
    }

    #[test]
    fn unknown_critical_features_fail_closed() {
        let mut capsule = capsule();
        capsule.critical_features = 0b10;
        assert!(matches!(
            capsule.validate(),
            Err(Error::UnknownCriticalFeature { bits: 0b10 })
        ));
    }

    #[test]
    fn a_producer_cannot_declare_raw_logs_public() {
        // Evidence kind 3 is `raw-log-text`, whose registry floor is P3.
        let item = evidence(3, 0, 1, 8);
        assert_eq!(item.effective_class(), cc_schema::PrivacyClass::P3);

        let mut capsule = capsule();
        capsule.evidence.push(item);
        capsule.privacy.max_class = 3;
        assert!(matches!(
            capsule.validate(),
            Err(Error::ClassAboveProfile { kind: 3, .. })
        ));
    }

    #[test]
    fn the_manifest_cannot_understate_what_is_present() {
        let mut capsule = capsule();
        capsule.profile = 4; // local-full permits P3
        capsule.evidence.push(evidence(3, 3, 1, 8));
        capsule.privacy.max_class = 0;
        assert!(matches!(
            capsule.validate(),
            Err(Error::ManifestUnderstatesClass { .. })
        ));
    }

    #[test]
    fn the_budget_drops_low_priority_evidence_and_keeps_identity() {
        let mut capsule = capsule();
        capsule.evidence = vec![
            evidence(2, 1, 9, 64),  // high priority, keep
            evidence(2, 1, 1, 512), // low priority, drop first
            evidence(2, 1, 5, 512),
        ];
        let fingerprints = capsule.fingerprints.clone();

        capsule.apply_evidence_budget(700, |bytes| bytes.len() as u64);

        assert!(capsule.encode().len() <= 700);
        assert_eq!(capsule.evidence.len(), 1);
        assert_eq!(capsule.evidence[0].priority, 9);
        assert_eq!(capsule.privacy.dropped_evidence, 2);
        assert_eq!(capsule.fingerprints, fingerprints, "identity must survive");
        assert!(!capsule.frames.is_empty());
    }

    #[test]
    fn the_budget_drops_material_the_profile_forbids_even_when_it_fits() {
        let mut capsule = capsule();
        capsule.evidence = vec![evidence(5, 4, 9, 4)]; // core-dump reference, P4
        capsule.apply_evidence_budget(64 * 1024, |bytes| bytes.len() as u64);
        assert!(capsule.evidence.is_empty());
        assert_eq!(capsule.privacy.dropped_evidence, 1);
    }

    #[test]
    fn fingerprints_ignore_boot_local_variation() {
        let mut a = capsule();
        let mut b = capsule();
        // A different boot: different capsule id, sequence, uptime and severity ordering.
        b.capsule_id = [0x77; 16];
        b.event.sequence = Some(42);
        b.time_info = Some(TimeInfo {
            uptime_bucket: Some(9),
            day: Some(20_000),
        });
        a.recompute_fingerprints();
        b.recompute_fingerprints();
        assert_eq!(a.fingerprints.strict, b.fingerprints.strict);
        assert_eq!(a.fingerprints.family, b.fingerprints.family);
    }

    #[test]
    fn transport_size_is_checked_against_the_profile() {
        let capsule = capsule();
        assert!(capsule.check_transport_size(1024).is_ok());
        assert!(matches!(
            capsule.check_transport_size(64 * 1024),
            Err(Error::OverBudget { .. })
        ));
    }
}
