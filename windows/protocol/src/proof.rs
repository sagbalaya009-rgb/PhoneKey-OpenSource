use std::collections::BTreeMap;

use p256::ecdsa::SigningKey;

use crate::cbor::{CborValue, decode, encode};
use crate::crypto::{P256_SIGNATURE_LEN, sign_login_challenge, verify_login_challenge};
use crate::error::ProtocolError;
use crate::messages::{LoginChallenge, PROTOCOL_VERSION};
use crate::types::{DEVICE_ID_LEN, DeviceId, SESSION_ID_LEN, SessionId};

pub const MESSAGE_TYPE_LOGIN_PROOF: u64 = 2;

const FIELD_VERSION: u16 = 1;
const FIELD_MESSAGE_TYPE: u16 = 2;
const FIELD_ANDROID_DEVICE_ID: u16 = 3;
const FIELD_SESSION_ID: u16 = 4;
const FIELD_SIGNATURE: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginProof {
    pub android_device_id: DeviceId,
    pub session_id: SessionId,
    pub signature: [u8; P256_SIGNATURE_LEN],
}

impl LoginProof {
    pub fn to_cbor(&self) -> CborValue {
        let mut map = BTreeMap::new();

        map.insert(FIELD_VERSION, CborValue::Unsigned(PROTOCOL_VERSION));

        map.insert(
            FIELD_MESSAGE_TYPE,
            CborValue::Unsigned(MESSAGE_TYPE_LOGIN_PROOF),
        );

        map.insert(
            FIELD_ANDROID_DEVICE_ID,
            CborValue::Bytes(self.android_device_id.0.to_vec()),
        );

        map.insert(
            FIELD_SESSION_ID,
            CborValue::Bytes(self.session_id.0.to_vec()),
        );

        map.insert(FIELD_SIGNATURE, CborValue::Bytes(self.signature.to_vec()));

        CborValue::Map(map)
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, ProtocolError> {
        let map = match value {
            CborValue::Map(map) => map,
            _ => return Err(ProtocolError::InvalidFieldType(0)),
        };

        for key in map.keys() {
            if !matches!(
                *key,
                FIELD_VERSION
                    | FIELD_MESSAGE_TYPE
                    | FIELD_ANDROID_DEVICE_ID
                    | FIELD_SESSION_ID
                    | FIELD_SIGNATURE
            ) {
                return Err(ProtocolError::UnexpectedField(*key));
            }
        }

        let version = unsigned_field(map, FIELD_VERSION)?;

        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidFieldValue(FIELD_VERSION));
        }

        let message_type = unsigned_field(map, FIELD_MESSAGE_TYPE)?;

        if message_type != MESSAGE_TYPE_LOGIN_PROOF {
            return Err(ProtocolError::InvalidFieldValue(FIELD_MESSAGE_TYPE));
        }

        let android_device_id =
            DeviceId(fixed_bytes::<DEVICE_ID_LEN>(map, FIELD_ANDROID_DEVICE_ID)?);

        let session_id = SessionId(fixed_bytes::<SESSION_ID_LEN>(map, FIELD_SESSION_ID)?);

        let signature = fixed_bytes::<P256_SIGNATURE_LEN>(map, FIELD_SIGNATURE)?;

        Ok(Self {
            android_device_id,
            session_id,
            signature,
        })
    }
}

pub fn create_login_proof(
    signing_key: &SigningKey,
    android_device_id: DeviceId,
    challenge: &LoginChallenge,
) -> Result<LoginProof, ProtocolError> {
    let signature = sign_login_challenge(signing_key, challenge)?;

    Ok(LoginProof {
        android_device_id,
        session_id: challenge.session_id,
        signature,
    })
}

pub fn verify_login_proof(
    proof: &LoginProof,
    expected_android_device_id: &DeviceId,
    public_key_sec1: &[u8],
    challenge: &LoginChallenge,
) -> Result<(), ProtocolError> {
    if &proof.android_device_id != expected_android_device_id {
        return Err(ProtocolError::ProofBindingMismatch);
    }

    if proof.session_id != challenge.session_id {
        return Err(ProtocolError::ProofBindingMismatch);
    }

    verify_login_challenge(public_key_sec1, challenge, &proof.signature)
}

pub fn encode_login_proof(proof: &LoginProof) -> Result<Vec<u8>, ProtocolError> {
    encode(&proof.to_cbor())
}

pub fn decode_login_proof(data: &[u8]) -> Result<LoginProof, ProtocolError> {
    let value = decode(data)?;
    LoginProof::from_cbor(&value)
}

fn unsigned_field(map: &BTreeMap<u16, CborValue>, key: u16) -> Result<u64, ProtocolError> {
    match map.get(&key) {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        Some(_) => Err(ProtocolError::InvalidFieldType(key)),
        None => Err(ProtocolError::MissingField(key)),
    }
}

fn bytes_field(map: &BTreeMap<u16, CborValue>, key: u16) -> Result<Vec<u8>, ProtocolError> {
    match map.get(&key) {
        Some(CborValue::Bytes(value)) => Ok(value.clone()),
        Some(_) => Err(ProtocolError::InvalidFieldType(key)),
        None => Err(ProtocolError::MissingField(key)),
    }
}

fn fixed_bytes<const N: usize>(
    map: &BTreeMap<u16, CborValue>,
    key: u16,
) -> Result<[u8; N], ProtocolError> {
    let bytes = bytes_field(map, key)?;

    if bytes.len() != N {
        return Err(ProtocolError::InvalidFieldLength(key));
    }

    let mut output = [0u8; N];
    output.copy_from_slice(&bytes);

    Ok(output)
}
