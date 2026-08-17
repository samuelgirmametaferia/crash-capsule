//! Deterministic CBOR for Crash Capsule.
//!
//! Two properties matter here and nothing else does:
//!
//! 1. **Encoding is reproducible.** Two conforming implementations must derive the same byte
//!    string from the same value, because fingerprints are hashes over these bytes
//!    (RFC 8949 §4.2.1 core deterministic encoding requirements).
//! 2. **Decoding is hostile-input safe.** A capsule can arrive from a screen photographed by a
//!    stranger, so the decoder is bounded in depth, item count and string length, rejects
//!    non-canonical encodings outright, and supports only the subset of CBOR the schema uses.
//!
//! Supported major types: unsigned, negative, byte string, text string, array, map, and the
//! simple values `false`, `true` and `null`. Floats, tags, indefinite lengths and other simple
//! values are rejected: the schema does not use them, and every construct the parser accepts is
//! attack surface.

#![deny(missing_docs)]

mod decode;
mod encode;
mod value;

pub use decode::{decode, decode_with, Limits};
pub use encode::encode;
pub use value::Value;

/// Errors produced while encoding or decoding deterministic CBOR.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Input ended in the middle of an item.
    #[error("unexpected end of input at offset {offset}")]
    Truncated {
        /// Offset at which more bytes were required.
        offset: usize,
    },
    /// Bytes remained after a complete top-level item was decoded.
    #[error("{remaining} trailing byte(s) after the top-level item")]
    TrailingBytes {
        /// Number of unconsumed bytes.
        remaining: usize,
    },
    /// A major type or additional-information value the schema never uses.
    #[error("unsupported CBOR construct 0x{byte:02x} at offset {offset}")]
    Unsupported {
        /// The offending initial byte.
        byte: u8,
        /// Offset of the offending byte.
        offset: usize,
    },
    /// An argument was not encoded in the shortest possible form.
    #[error("non-canonical integer encoding at offset {offset}")]
    NonCanonicalInt {
        /// Offset of the offending item.
        offset: usize,
    },
    /// Map keys were not in canonical (bytewise, by encoded key) order.
    #[error("map keys out of canonical order at offset {offset}")]
    UnsortedMapKeys {
        /// Offset of the offending map.
        offset: usize,
    },
    /// The same map key appeared twice.
    #[error("duplicate map key at offset {offset}")]
    DuplicateMapKey {
        /// Offset of the offending map.
        offset: usize,
    },
    /// A text string was not valid UTF-8.
    #[error("invalid UTF-8 in text string at offset {offset}")]
    InvalidUtf8 {
        /// Offset of the offending string.
        offset: usize,
    },
    /// A structural limit was exceeded.
    #[error("limit exceeded: {limit}")]
    LimitExceeded {
        /// Which limit was hit.
        limit: &'static str,
    },
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
