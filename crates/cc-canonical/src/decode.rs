//! Strict, bounded CBOR decoding.

use crate::{Error, Result, Value};

/// Structural limits applied while decoding.
///
/// The defaults are sized for the largest `local-full` capsule; visual profiles are far smaller.
/// Callers parsing untrusted optical input should tighten `max_input` to the profile budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting depth of arrays and maps.
    pub max_depth: usize,
    /// Maximum number of decoded items in the whole object.
    pub max_items: usize,
    /// Maximum length of any single byte or text string.
    pub max_string: usize,
    /// Maximum accepted input length.
    pub max_input: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_items: 4096,
            max_string: 65536,
            max_input: 262_144,
        }
    }
}

/// Decodes deterministic CBOR with the default [`Limits`].
pub fn decode(input: &[u8]) -> Result<Value> {
    decode_with(input, Limits::default())
}

/// Decodes deterministic CBOR, rejecting any non-canonical encoding.
///
/// The decoder is deliberately strict: an input that decodes to the right value but was not
/// encoded canonically is an error, because fingerprints are computed over these bytes and a
/// second encoding of the same value would otherwise hash differently.
pub fn decode_with(input: &[u8], limits: Limits) -> Result<Value> {
    if input.len() > limits.max_input {
        return Err(Error::LimitExceeded { limit: "max_input" });
    }
    let mut decoder = Decoder {
        input,
        offset: 0,
        items: 0,
        limits,
    };
    let value = decoder.value(0)?;
    let remaining = input.len() - decoder.offset;
    if remaining > 0 {
        return Err(Error::TrailingBytes { remaining });
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    items: usize,
    limits: Limits,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > self.limits.max_depth {
            return Err(Error::LimitExceeded { limit: "max_depth" });
        }
        self.items += 1;
        if self.items > self.limits.max_items {
            return Err(Error::LimitExceeded { limit: "max_items" });
        }

        let start = self.offset;
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;

        match major {
            0 => Ok(Value::Unsigned(self.argument(additional, start)?)),
            1 => Ok(Value::Negative(self.argument(additional, start)?)),
            2 => {
                let len = self.length(additional, start)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.length(additional, start)?;
                let raw = self.take(len)?;
                let text = core::str::from_utf8(raw)
                    .map_err(|_| Error::InvalidUtf8 { offset: start })?
                    .to_owned();
                Ok(Value::Text(text))
            }
            4 => {
                let len = self.length(additional, start)?;
                let mut items = Vec::new();
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.length(additional, start)?;
                let mut entries: Vec<(Value, Value)> = Vec::new();
                let mut previous_key: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let key_start = self.offset;
                    let key = self.value(depth + 1)?;
                    let key_bytes = self
                        .input
                        .get(key_start..self.offset)
                        .ok_or(Error::Truncated { offset: key_start })?
                        .to_vec();
                    if let Some(previous) = &previous_key {
                        match key_bytes.cmp(previous) {
                            core::cmp::Ordering::Less => {
                                return Err(Error::UnsortedMapKeys { offset: start })
                            }
                            core::cmp::Ordering::Equal => {
                                return Err(Error::DuplicateMapKey { offset: start })
                            }
                            core::cmp::Ordering::Greater => {}
                        }
                    }
                    previous_key = Some(key_bytes);
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            7 => match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::Unsupported {
                    byte: initial,
                    offset: start,
                }),
            },
            // Major type 6 (tags) is never used by the schema.
            _ => Err(Error::Unsupported {
                byte: initial,
                offset: start,
            }),
        }
    }

    /// Reads an argument, rejecting indefinite lengths and non-shortest encodings.
    fn argument(&mut self, additional: u8, start: usize) -> Result<u64> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 {
                    return Err(Error::NonCanonicalInt { offset: start });
                }
                Ok(value)
            }
            25 => {
                let bytes = self.take(2)?;
                let value = u64::from(u16::from_be_bytes([get(bytes, 0)?, get(bytes, 1)?]));
                if value <= 0xff {
                    return Err(Error::NonCanonicalInt { offset: start });
                }
                Ok(value)
            }
            26 => {
                let bytes = self.take(4)?;
                let value = u64::from(u32::from_be_bytes([
                    get(bytes, 0)?,
                    get(bytes, 1)?,
                    get(bytes, 2)?,
                    get(bytes, 3)?,
                ]));
                if value <= 0xffff {
                    return Err(Error::NonCanonicalInt { offset: start });
                }
                Ok(value)
            }
            27 => {
                let bytes = self.take(8)?;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(bytes);
                let value = u64::from_be_bytes(buf);
                if value <= 0xffff_ffff {
                    return Err(Error::NonCanonicalInt { offset: start });
                }
                Ok(value)
            }
            // 28..=30 are reserved; 31 is the indefinite-length marker.
            _ => Err(Error::Unsupported {
                byte: additional,
                offset: start,
            }),
        }
    }

    fn length(&mut self, additional: u8, start: usize) -> Result<usize> {
        let raw = self.argument(additional, start)?;
        let len = usize::try_from(raw).map_err(|_| Error::LimitExceeded {
            limit: "max_string",
        })?;
        if len > self.limits.max_string || len > self.limits.max_input {
            return Err(Error::LimitExceeded {
                limit: "max_string",
            });
        }
        Ok(len)
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = *self.input.get(self.offset).ok_or(Error::Truncated {
            offset: self.offset,
        })?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self.offset.checked_add(len).ok_or(Error::Truncated {
            offset: self.offset,
        })?;
        let slice = self.input.get(self.offset..end).ok_or(Error::Truncated {
            offset: self.offset,
        })?;
        self.offset = end;
        Ok(slice)
    }
}

fn get(bytes: &[u8], index: usize) -> Result<u8> {
    bytes
        .get(index)
        .copied()
        .ok_or(Error::Truncated { offset: index })
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
    use crate::encode;

    #[test]
    fn round_trips_canonical_encodings() {
        let value = Value::Map(vec![
            (Value::Unsigned(0), Value::Unsigned(1)),
            (Value::Unsigned(1), Value::text("x")),
            (
                Value::Unsigned(2),
                Value::Array(vec![Value::int(-1), Value::bytes(vec![1, 2, 3])]),
            ),
        ]);
        let bytes = encode(&value);
        assert_eq!(decode(&bytes).expect("decodes"), value);
    }

    #[test]
    fn rejects_non_canonical_integer_encoding() {
        // 1 encoded in a two-byte argument instead of the shortest form.
        assert!(matches!(
            decode(&[0x18, 0x01]),
            Err(Error::NonCanonicalInt { .. })
        ));
    }

    #[test]
    fn rejects_indefinite_length_and_tags_and_floats() {
        assert!(matches!(decode(&[0x5f]), Err(Error::Unsupported { .. }))); // indefinite bstr
        assert!(matches!(
            decode(&[0xc0, 0x00]),
            Err(Error::Unsupported { .. })
        )); // tag
        assert!(matches!(
            decode(&[0xfa, 0x00, 0x00, 0x00, 0x00]),
            Err(Error::Unsupported { .. })
        )); // float
    }

    #[test]
    fn rejects_unsorted_and_duplicate_map_keys() {
        assert!(matches!(
            decode(&[0xa2, 0x0a, 0xf6, 0x02, 0xf6]),
            Err(Error::UnsortedMapKeys { .. })
        ));
        assert!(matches!(
            decode(&[0xa2, 0x02, 0xf6, 0x02, 0xf6]),
            Err(Error::DuplicateMapKey { .. })
        ));
    }

    #[test]
    fn rejects_truncated_and_trailing_input() {
        assert!(matches!(
            decode(&[0x43, 0x01]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            decode(&[0x00, 0x00]),
            Err(Error::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn enforces_depth_and_item_limits() {
        // 20 nested single-element arrays exceeds the default depth of 16.
        let mut value = Value::Null;
        for _ in 0..20 {
            value = Value::Array(vec![value]);
        }
        let bytes = encode(&value);
        assert!(matches!(
            decode(&bytes),
            Err(Error::LimitExceeded { limit: "max_depth" })
        ));

        let wide = Value::Array((0..100).map(Value::Unsigned).collect());
        let limits = Limits {
            max_items: 10,
            ..Limits::default()
        };
        assert!(matches!(
            decode_with(&encode(&wide), limits),
            Err(Error::LimitExceeded { limit: "max_items" })
        ));
    }

    #[test]
    fn a_declared_length_larger_than_the_input_cannot_allocate() {
        // Declares a 4 GiB byte string in three bytes; must fail on limits, not allocate.
        assert!(matches!(
            decode(&[0x5a, 0xff, 0xff, 0xff, 0xff]),
            Err(Error::LimitExceeded { .. })
        ));
    }
}
