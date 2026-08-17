//! Conformance of this implementation against the committed corpus.
//!
//! These tests are the contract a second implementation has to meet: the committed bytes decode,
//! re-encode identically, validate, and produce the recorded fingerprints; and every malformed
//! input is rejected.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fs;

use cc_capsule::Capsule;
use cc_vectors::cases;

#[test]
fn the_committed_corpus_matches_the_generator() {
    let root = cc_vectors::repository_root();
    let mut stale = Vec::new();
    for (path, expected) in cc_vectors::generated_files() {
        match fs::read(root.join(&path)) {
            Ok(found) if found == expected => {}
            _ => stale.push(path.display().to_string()),
        }
    }
    assert!(
        stale.is_empty(),
        "corpus is out of date, run `cargo run -p cc-vectors`:\n{}",
        stale.join("\n")
    );
}

#[test]
fn the_corpus_is_large_enough_to_be_useful() {
    assert!(
        cases::canonical_cases().len() >= 50,
        "the specification requires at least 50 canonical vectors"
    );
    assert!(cases::malformed_cases().len() >= 12);
}

#[test]
fn every_canonical_vector_round_trips_and_validates() {
    let root = cc_vectors::repository_root();
    for case in cases::canonical_cases() {
        let path = root.join(format!(
            "specification/test-vectors/canonical/{}.cbor",
            case.name
        ));
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));

        let decoded = Capsule::decode(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(
            decoded.encode(),
            bytes,
            "{}: re-encoding is not byte-identical",
            case.name
        );
        decoded
            .validate()
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));

        let mut recomputed = decoded.clone();
        recomputed.recompute_fingerprints();
        assert_eq!(
            recomputed.fingerprints, decoded.fingerprints,
            "{}: stored fingerprints do not match recomputation",
            case.name
        );
    }
}

#[test]
fn every_malformed_vector_is_rejected() {
    let root = cc_vectors::repository_root();
    for case in cases::malformed_cases() {
        let path = root.join(format!(
            "specification/test-vectors/malformed/{}.cbor",
            case.name
        ));
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            Capsule::decode(&bytes).is_err(),
            "{} was accepted but must be rejected: {}",
            case.name,
            case.note
        );
    }
}

#[test]
fn no_visual_vector_carries_secret_or_restricted_material() {
    for case in cases::canonical_cases() {
        let Some(spec) = cc_schema::profile(case.capsule.profile) else {
            panic!("{}: unknown profile", case.name);
        };
        if !spec.name.starts_with("visual-") && spec.name != "panic-minimal" {
            continue;
        }
        for item in &case.capsule.evidence {
            assert!(
                item.effective_class() <= cc_schema::PrivacyClass::P2,
                "{}: evidence kind {} is {:?} under profile {}",
                case.name,
                item.kind,
                item.effective_class(),
                spec.name
            );
        }
    }
}

#[test]
fn fingerprint_vectors_reproduce_from_their_material() {
    use sha2::{Digest, Sha256};

    let root = cc_vectors::repository_root();
    for case in cases::fingerprint_cases() {
        let path = root.join(format!(
            "specification/test-vectors/fingerprint/{}.material.cbor",
            case.name
        ));
        let material = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(material, case.material, "{}: material drifted", case.name);
        let digest: [u8; 32] = Sha256::digest(&material).into();
        assert_eq!(digest, case.fingerprint, "{}", case.name);
    }
}
