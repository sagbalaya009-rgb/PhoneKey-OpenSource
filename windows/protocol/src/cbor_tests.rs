use std::collections::BTreeMap;

use crate::cbor::{CborValue, decode, encode};
use crate::error::ProtocolError;
use crate::types::{MAX_MESSAGE_SIZE, MAX_NESTING_DEPTH};

#[test]
fn unsigned_integer_boundaries_encode_canonically() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65_535, &[0x19, 0xff, 0xff]),
        (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (u32::MAX as u64, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];

    for (value, expected) in cases {
        let encoded = encode(&CborValue::Unsigned(*value)).unwrap();
        assert_eq!(&encoded, expected);

        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, CborValue::Unsigned(*value));
    }
}

#[test]
fn byte_string_length_boundaries_are_canonical() {
    let value_23 = CborValue::Bytes(vec![0xaa; 23]);
    let encoded_23 = encode(&value_23).unwrap();
    assert_eq!(encoded_23[0], 0x57);

    let value_24 = CborValue::Bytes(vec![0xaa; 24]);
    let encoded_24 = encode(&value_24).unwrap();
    assert_eq!(&encoded_24[..2], &[0x58, 0x18]);

    let value_255 = CborValue::Bytes(vec![0xaa; 255]);
    let encoded_255 = encode(&value_255).unwrap();
    assert_eq!(&encoded_255[..2], &[0x58, 0xff]);

    let value_256 = CborValue::Bytes(vec![0xaa; 256]);
    let encoded_256 = encode(&value_256).unwrap();
    assert_eq!(&encoded_256[..3], &[0x59, 0x01, 0x00]);
}

#[test]
fn text_string_length_boundaries_are_canonical() {
    let value_23 = CborValue::Text("a".repeat(23));
    let encoded_23 = encode(&value_23).unwrap();
    assert_eq!(encoded_23[0], 0x77);

    let value_24 = CborValue::Text("a".repeat(24));
    let encoded_24 = encode(&value_24).unwrap();
    assert_eq!(&encoded_24[..2], &[0x78, 0x18]);

    let value_255 = CborValue::Text("a".repeat(255));
    let encoded_255 = encode(&value_255).unwrap();
    assert_eq!(&encoded_255[..2], &[0x78, 0xff]);

    let value_256 = CborValue::Text("a".repeat(256));
    let encoded_256 = encode(&value_256).unwrap();
    assert_eq!(&encoded_256[..3], &[0x79, 0x01, 0x00]);
}

#[test]
fn valid_values_round_trip() {
    let mut map = BTreeMap::new();
    map.insert(1, CborValue::Unsigned(42));
    map.insert(2, CborValue::Bytes(vec![1, 2, 3, 4]));
    map.insert(3, CborValue::Text("PhoneKey".to_owned()));

    let values = [
        CborValue::Unsigned(0),
        CborValue::Unsigned(u64::MAX),
        CborValue::Bytes(vec![]),
        CborValue::Bytes(vec![1, 2, 3]),
        CborValue::Text(String::new()),
        CborValue::Text("hello".to_owned()),
        CborValue::Map(map),
    ];

    for value in values {
        let encoded = encode(&value).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn map_encoding_is_sorted_by_key() {
    let mut map = BTreeMap::new();
    map.insert(10, CborValue::Unsigned(1));
    map.insert(2, CborValue::Unsigned(2));

    let encoded = encode(&CborValue::Map(map)).unwrap();

    assert_eq!(encoded, vec![0xa2, 0x02, 0x02, 0x0a, 0x01]);
}

#[test]
fn duplicate_map_keys_are_rejected() {
    let input = [0xa2, 0x01, 0x00, 0x01, 0x00];

    assert_eq!(decode(&input), Err(ProtocolError::NonCanonicalEncoding));
}

#[test]
fn descending_map_keys_are_rejected() {
    let input = [0xa2, 0x02, 0x00, 0x01, 0x00];

    assert_eq!(decode(&input), Err(ProtocolError::NonCanonicalEncoding));
}

#[test]
fn non_integer_map_key_is_rejected() {
    let input = [0xa1, 0x61, b'a', 0x00];

    assert_eq!(decode(&input), Err(ProtocolError::InvalidMapKey));
}

#[test]
fn map_key_larger_than_u16_is_rejected() {
    let input = [0xa1, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x00];

    assert_eq!(decode(&input), Err(ProtocolError::InvalidMapKey));
}

#[test]
fn non_shortest_unsigned_encodings_are_rejected() {
    let cases: &[&[u8]] = &[
        &[0x18, 0x00],
        &[0x18, 0x17],
        &[0x19, 0x00, 0xff],
        &[0x1a, 0x00, 0x00, 0xff, 0xff],
        &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
    ];

    for input in cases {
        assert_eq!(decode(input), Err(ProtocolError::NonCanonicalEncoding));
    }
}

#[test]
fn non_canonical_byte_string_length_is_rejected() {
    let input = [0x58, 0x01, 0xaa];

    assert_eq!(decode(&input), Err(ProtocolError::NonCanonicalEncoding));
}

#[test]
fn non_canonical_text_string_length_is_rejected() {
    let input = [0x78, 0x01, b'a'];

    assert_eq!(decode(&input), Err(ProtocolError::NonCanonicalEncoding));
}

#[test]
fn non_canonical_map_length_is_rejected() {
    let input = [0xb8, 0x01, 0x00, 0x00];

    assert_eq!(decode(&input), Err(ProtocolError::NonCanonicalEncoding));
}

#[test]
fn trailing_bytes_are_rejected() {
    let input = [0x00, 0x00];

    assert_eq!(decode(&input), Err(ProtocolError::Malformed));
}

#[test]
fn empty_input_is_rejected() {
    assert_eq!(decode(&[]), Err(ProtocolError::Malformed));
}

#[test]
fn truncated_integer_encodings_are_rejected() {
    let cases: &[&[u8]] = &[
        &[0x18],
        &[0x19, 0x01],
        &[0x1a, 0x00, 0x01],
        &[0x1b, 0x00, 0x00, 0x00],
    ];

    for input in cases {
        assert_eq!(decode(input), Err(ProtocolError::Malformed));
    }
}

#[test]
fn truncated_byte_string_is_rejected() {
    let input = [0x45, 0x01, 0x02, 0x03];

    assert_eq!(decode(&input), Err(ProtocolError::Malformed));
}

#[test]
fn truncated_text_string_is_rejected() {
    let input = [0x65, b'a', b'b', b'c'];

    assert_eq!(decode(&input), Err(ProtocolError::Malformed));
}

#[test]
fn truncated_map_key_is_rejected() {
    let input = [0xa1];

    assert_eq!(decode(&input), Err(ProtocolError::Malformed));
}

#[test]
fn truncated_map_value_is_rejected() {
    let input = [0xa1, 0x01];

    assert_eq!(decode(&input), Err(ProtocolError::Malformed));
}

#[test]
fn invalid_utf8_text_is_rejected() {
    let input = [0x61, 0xff];

    assert_eq!(decode(&input), Err(ProtocolError::Malformed));
}

#[test]
fn unsupported_types_are_rejected() {
    let cases: &[&[u8]] = &[
        &[0x20],                         // negative integer
        &[0x80],                         // array
        &[0xc0, 0x00],                   // tag
        &[0xf4],                         // false
        &[0xf5],                         // true
        &[0xf6],                         // null
        &[0xfa, 0x00, 0x00, 0x00, 0x00], // float
    ];

    for input in cases {
        assert_eq!(decode(input), Err(ProtocolError::UnsupportedType));
    }
}

#[test]
fn indefinite_lengths_are_rejected() {
    assert_eq!(decode(&[0x5f, 0xff]), Err(ProtocolError::UnsupportedType));

    assert_eq!(decode(&[0x7f, 0xff]), Err(ProtocolError::UnsupportedType));

    assert_eq!(decode(&[0xbf, 0xff]), Err(ProtocolError::UnsupportedType));
}

#[test]
fn oversized_input_is_rejected_before_parsing() {
    let input = vec![0x00; MAX_MESSAGE_SIZE + 1];

    assert_eq!(decode(&input), Err(ProtocolError::OversizedMessage));
}

#[test]
fn oversized_output_is_rejected() {
    let value = CborValue::Bytes(vec![0xaa; MAX_MESSAGE_SIZE]);

    assert_eq!(encode(&value), Err(ProtocolError::OversizedMessage));
}

#[test]
fn exactly_maximum_encoded_size_is_allowed() {
    // 2045 bytes of payload + a 3-byte byte-string header = 2048 bytes.
    let value = CborValue::Bytes(vec![0xaa; MAX_MESSAGE_SIZE - 3]);

    let encoded = encode(&value).unwrap();

    assert_eq!(encoded.len(), MAX_MESSAGE_SIZE);
    assert_eq!(decode(&encoded).unwrap(), value);
}

fn nested_map(depth: usize) -> CborValue {
    let mut value = CborValue::Unsigned(0);

    for _ in 0..depth {
        let mut map = BTreeMap::new();
        map.insert(1, value);
        value = CborValue::Map(map);
    }

    value
}

fn encoded_nested_map(depth: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(depth * 2 + 1);

    for _ in 0..depth {
        bytes.push(0xa1);
        bytes.push(0x01);
    }

    bytes.push(0x00);
    bytes
}

#[test]
fn nesting_depth_eight_is_allowed_for_encoding() {
    let value = nested_map(MAX_NESTING_DEPTH);

    assert!(encode(&value).is_ok());
}

#[test]
fn nesting_depth_nine_is_rejected_for_encoding() {
    let value = nested_map(MAX_NESTING_DEPTH + 1);

    assert_eq!(encode(&value), Err(ProtocolError::NestingTooDeep));
}

#[test]
fn nesting_depth_eight_is_allowed_for_decoding() {
    let input = encoded_nested_map(MAX_NESTING_DEPTH);

    assert!(decode(&input).is_ok());
}

#[test]
fn nesting_depth_nine_is_rejected_for_decoding() {
    let input = encoded_nested_map(MAX_NESTING_DEPTH + 1);

    assert_eq!(decode(&input), Err(ProtocolError::NestingTooDeep));
}
