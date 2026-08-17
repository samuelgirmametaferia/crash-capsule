//! Crash Capsule schema constants.
//!
//! Everything in this crate is derived from `specification/registry.toml`: wire keys,
//! profile budgets, and the **minimum** privacy class of every standard field. The
//! normative rule enforced here is
//!
//! ```text
//! effective_class = max(schema_minimum_class, producer_declared_class)
//! ```
//!
//! A producer may raise a field's class; it can never lower the registry floor.

#![deny(missing_docs)]

include!(concat!(env!("OUT_DIR"), "/registry.rs"));

/// Privacy class of a field or evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrivacyClass {
    /// Public diagnostic data.
    P0,
    /// Pseudonymous or low-risk diagnostic data.
    P1,
    /// Personal-context risk; redacted or tokenised by default.
    P2,
    /// Secret-risk data; omitted unless explicitly justified.
    P3,
    /// Restricted artifact; never transported optically by default.
    P4,
}

impl PrivacyClass {
    /// Returns the class for a registry identifier, or `None` if it is not a valid class.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::P0),
            1 => Some(Self::P1),
            2 => Some(Self::P2),
            3 => Some(Self::P3),
            4 => Some(Self::P4),
            _ => None,
        }
    }

    /// Returns the registry identifier of this class.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
            Self::P2 => 2,
            Self::P3 => 3,
            Self::P4 => 4,
        }
    }

    /// Applies the normative combination rule: the effective class is the stricter of the
    /// registry floor and whatever the producer declared.
    #[must_use]
    pub fn effective(schema_minimum: Self, producer_declared: Self) -> Self {
        schema_minimum.max(producer_declared)
    }
}

/// Size and privacy budget of a capsule profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSpec {
    /// Wire identifier of the profile.
    pub id: u64,
    /// Registry name, e.g. `visual-standard`.
    pub name: &'static str,
    /// Size a producer should aim for, after redaction and compression.
    pub target_bytes: u64,
    /// Hard limit, applied after redaction and compression but before outer FEC.
    pub max_bytes: u64,
    /// Highest class a field may carry and still be emitted under this profile.
    pub max_class: u8,
}

impl ProfileSpec {
    /// Highest privacy class this profile may carry.
    ///
    /// # Panics
    ///
    /// Never in practice: the generated table only contains valid class identifiers, and a
    /// registry that violated that would fail the build.
    #[must_use]
    pub fn max_privacy_class(&self) -> PrivacyClass {
        match PrivacyClass::from_id(self.max_class) {
            Some(class) => class,
            None => PrivacyClass::P0,
        }
    }
}

/// Looks up a profile by wire identifier.
#[must_use]
pub fn profile(id: u64) -> Option<&'static ProfileSpec> {
    PROFILES.iter().find(|p| p.id == id)
}

/// Looks up a profile by registry name.
#[must_use]
pub fn profile_by_name(name: &str) -> Option<&'static ProfileSpec> {
    PROFILES.iter().find(|p| p.name == name)
}

/// Returns the registry minimum privacy class for a field path such as `component.executable`.
#[must_use]
pub fn privacy_floor(path: &str) -> Option<PrivacyClass> {
    FIELDS
        .iter()
        .find(|(p, _, _)| *p == path)
        .and_then(|(_, class, _)| PrivacyClass::from_id(*class))
}

/// Returns the registry minimum privacy class for an evidence kind.
#[must_use]
pub fn evidence_kind_floor(kind: u64) -> Option<PrivacyClass> {
    EVIDENCE_KINDS
        .iter()
        .find(|(id, _, _)| *id == kind)
        .and_then(|(_, _, class)| PrivacyClass::from_id(*class))
}

/// Returns the name registered for an evidence kind.
#[must_use]
pub fn evidence_kind_name(kind: u64) -> Option<&'static str> {
    EVIDENCE_KINDS
        .iter()
        .find(|(id, _, _)| *id == kind)
        .map(|(_, name, _)| *name)
}

/// Returns the name registered for a category identifier used in the privacy manifest.
#[must_use]
pub fn category_name(id: u64) -> Option<&'static str> {
    CATEGORIES
        .iter()
        .find(|(cid, _)| *cid == id)
        .map(|(_, name)| *name)
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

    #[test]
    fn effective_class_never_falls_below_the_registry_floor() {
        // A producer marking the environment as public must not succeed.
        let floor = PrivacyClass::P3;
        assert_eq!(
            PrivacyClass::effective(floor, PrivacyClass::P0),
            PrivacyClass::P3
        );
        // Raising is allowed.
        assert_eq!(
            PrivacyClass::effective(floor, PrivacyClass::P4),
            PrivacyClass::P4
        );
    }

    #[test]
    fn registry_floors_match_the_specification() {
        assert_eq!(
            privacy_floor("capsule.schema_major"),
            Some(PrivacyClass::P0)
        );
        assert_eq!(
            privacy_floor("component.executable"),
            Some(PrivacyClass::P1)
        );
        assert_eq!(privacy_floor("system.hardware"), Some(PrivacyClass::P1));
        assert_eq!(privacy_floor("nonexistent.field"), None);
    }

    #[test]
    fn evidence_kinds_carry_their_floors() {
        assert_eq!(evidence_kind_floor(3), Some(PrivacyClass::P3)); // raw-log-text
        assert_eq!(evidence_kind_floor(5), Some(PrivacyClass::P4)); // core-dump
    }

    #[test]
    fn visual_profiles_never_permit_secret_or_restricted_material() {
        for spec in PROFILES.iter().filter(|p| p.name.starts_with("visual-")) {
            assert!(
                spec.max_privacy_class() <= PrivacyClass::P2,
                "{} allows {:?}",
                spec.name,
                spec.max_privacy_class()
            );
        }
        let panic_minimal = profile_by_name("panic-minimal").expect("profile registered");
        assert!(panic_minimal.max_privacy_class() <= PrivacyClass::P1);
        assert!(panic_minimal.max_bytes <= 2560);
    }

    #[test]
    fn field_paths_are_unique() {
        // Key uniqueness within a map is enforced at build time; this guards the paths that
        // the privacy floor lookup keys on.
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for (path, _, _) in FIELDS {
            assert!(seen.insert(path), "duplicate field path {path}");
        }
    }

    #[test]
    fn generated_keys_match_the_specification() {
        assert_eq!(keys::capsule::FINGERPRINTS, 11);
        assert_eq!(keys::component::BUILD_ID, 3);
        assert_eq!(keys::frame::OFFSET, 2);
    }
}
