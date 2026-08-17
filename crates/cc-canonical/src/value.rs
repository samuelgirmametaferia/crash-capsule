//! The CBOR data model subset used by Crash Capsule.

/// A CBOR value restricted to the constructs the Crash Capsule schema uses.
///
/// Maps are held as a vector of pairs rather than a `BTreeMap` because canonical map order is
/// defined over the *encoded* key bytes, not over the logical value ordering. [`crate::encode`]
/// performs that sort, so callers may build maps in whatever order is convenient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1, representing `-1 - n` for the stored `n`.
    Negative(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5.
    Map(Vec<(Value, Value)>),
    /// Simple value `false` or `true`.
    Bool(bool),
    /// Simple value `null`.
    Null,
}

impl Value {
    /// Builds a value from a signed integer, choosing the correct major type.
    #[must_use]
    pub fn int(value: i64) -> Self {
        if value >= 0 {
            Self::Unsigned(value.unsigned_abs())
        } else {
            // -1 - n == value  =>  n == -1 - value, computed without overflow at i64::MIN.
            Self::Negative(value.unsigned_abs() - 1)
        }
    }

    /// Builds a text value.
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Builds a byte-string value.
    #[must_use]
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// Returns the unsigned integer held by this value, if it is one.
    #[must_use]
    pub fn as_unsigned(&self) -> Option<u64> {
        match self {
            Self::Unsigned(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the signed integer held by this value, if it fits in an `i64`.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Unsigned(n) => i64::try_from(*n).ok(),
            Self::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// Returns the text held by this value, if it is a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the bytes held by this value, if it is a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the elements held by this value, if it is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the pairs held by this value, if it is a map.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// Looks up an integer-keyed map entry, the only key form the schema uses.
    #[must_use]
    pub fn get(&self, key: u64) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_unsigned() == Some(key))
            .map(|(_, v)| v)
    }
}
