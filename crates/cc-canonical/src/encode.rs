//! Deterministic CBOR encoding.

use crate::Value;

/// Encodes a value using RFC 8949 core deterministic encoding: definite lengths, shortest-form
/// arguments, and map keys sorted bytewise by their encoded representation.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Unsigned(n) => write_head(out, 0, *n),
        Value::Negative(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                write_value(out, item);
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                .iter()
                .map(|(k, v)| (encode(k), encode(v)))
                .collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            write_head(out, 5, encoded.len() as u64);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xff => {
            out.push(major | 24);
            out.push(argument as u8);
        }
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
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

    #[test]
    fn shortest_form_arguments() {
        assert_eq!(encode(&Value::Unsigned(0)), [0x00]);
        assert_eq!(encode(&Value::Unsigned(23)), [0x17]);
        assert_eq!(encode(&Value::Unsigned(24)), [0x18, 0x18]);
        assert_eq!(encode(&Value::Unsigned(256)), [0x19, 0x01, 0x00]);
        assert_eq!(encode(&Value::int(-1)), [0x20]);
        assert_eq!(encode(&Value::int(-11)), [0x2a]);
    }

    #[test]
    fn map_keys_are_sorted_by_encoded_bytes_regardless_of_insertion_order() {
        let a = Value::Map(vec![
            (Value::Unsigned(10), Value::Null),
            (Value::Unsigned(2), Value::Null),
        ]);
        let b = Value::Map(vec![
            (Value::Unsigned(2), Value::Null),
            (Value::Unsigned(10), Value::Null),
        ]);
        assert_eq!(encode(&a), encode(&b));
        assert_eq!(encode(&a), [0xa2, 0x02, 0xf6, 0x0a, 0xf6]);
    }
}
