use std::collections::BTreeMap;

use crate::cbor::{CborValue, decode, encode};
use crate::error::ProtocolError;
use crate::types::{
    DEVICE_ID_LEN, DeviceId, MAX_ACCOUNT_BINDING_LEN, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId,
};

pub const PROTOCOL_VERSION: u64 = 1;
pub const MESSAGE_TYPE_LOGIN_CHALLENGE: u64 = 1;

const FIELD_VERSION: u16 = 1;
const FIELD_MESSAGE_TYPE: u16 = 2;
const FIELD_WINDOWS_DEVICE_ID: u16 = 3;
const FIELD_SESSION_ID: u16 = 4;
const FIELD_NONCE: u16 = 5;
const FIELD_ISSUED_AT_MS: u16 = 6;
const FIELD_EXPIRES_AT_MS: u16 = 7;
const FIELD_OPERATION: u16 = 8;
const FIELD_ACCOUNT_BINDING: u16 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOperation {
    Logon,
    Unlock,
}

impl LoginOperation {
    fn as_u64(self) -> u64 {
        match self {
            Self::Logon => 1,
            Self::Unlock => 2,
        }
    }

    fn from_u64(value: u64) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Logon),
            2 => Ok(Self::Unlock),
            _ => Err(ProtocolError::InvalidFieldValue(FIELD_OPERATION)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginChallenge {
    pub windows_device_id: DeviceId,
    pub session_id: SessionId,
    pub nonce: Nonce,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub operation: LoginOperation,
    pub account_binding: Vec<u8>,
}

impl LoginChallenge {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(ProtocolError::InvalidFieldValue(FIELD_EXPIRES_AT_MS));
        }

        if self.account_binding.is_empty() || self.account_binding.len() > MAX_ACCOUNT_BINDING_LEN {
            return Err(ProtocolError::InvalidFieldLength(FIELD_ACCOUNT_BINDING));
        }

        Ok(())
    }

    pub fn to_cbor(&self) -> Result<CborValue, ProtocolError> {
        self.validate()?;

        let mut map = BTreeMap::new();

        map.insert(FIELD_VERSION, CborValue::Unsigned(PROTOCOL_VERSION));
        map.insert(
            FIELD_MESSAGE_TYPE,
            CborValue::Unsigned(MESSAGE_TYPE_LOGIN_CHALLENGE),
        );
        map.insert(
            FIELD_WINDOWS_DEVICE_ID,
            CborValue::Bytes(self.windows_device_id.0.to_vec()),
        );
        map.insert(
            FIELD_SESSION_ID,
            CborValue::Bytes(self.session_id.0.to_vec()),
        );
        map.insert(FIELD_NONCE, CborValue::Bytes(self.nonce.0.to_vec()));
        map.insert(FIELD_ISSUED_AT_MS, CborValue::Unsigned(self.issued_at_ms));
        map.insert(FIELD_EXPIRES_AT_MS, CborValue::Unsigned(self.expires_at_ms));
        map.insert(
            FIELD_OPERATION,
            CborValue::Unsigned(self.operation.as_u64()),
        );
        map.insert(
            FIELD_ACCOUNT_BINDING,
            CborValue::Bytes(self.account_binding.clone()),
        );

        Ok(CborValue::Map(map))
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
                    | FIELD_WINDOWS_DEVICE_ID
                    | FIELD_SESSION_ID
                    | FIELD_NONCE
                    | FIELD_ISSUED_AT_MS
                    | FIELD_EXPIRES_AT_MS
                    | FIELD_OPERATION
                    | FIELD_ACCOUNT_BINDING
            ) {
                return Err(ProtocolError::UnexpectedField(*key));
            }
        }

        let version = unsigned_field(map, FIELD_VERSION)?;
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidFieldValue(FIELD_VERSION));
        }

        let message_type = unsigned_field(map, FIELD_MESSAGE_TYPE)?;
        if message_type != MESSAGE_TYPE_LOGIN_CHALLENGE {
            return Err(ProtocolError::InvalidFieldValue(FIELD_MESSAGE_TYPE));
        }

        let windows_device_id =
            DeviceId(fixed_bytes::<DEVICE_ID_LEN>(map, FIELD_WINDOWS_DEVICE_ID)?);

        let session_id = SessionId(fixed_bytes::<SESSION_ID_LEN>(map, FIELD_SESSION_ID)?);

        let nonce = Nonce(fixed_bytes::<NONCE_LEN>(map, FIELD_NONCE)?);

        let issued_at_ms = unsigned_field(map, FIELD_ISSUED_AT_MS)?;
        let expires_at_ms = unsigned_field(map, FIELD_EXPIRES_AT_MS)?;

        let operation = LoginOperation::from_u64(unsigned_field(map, FIELD_OPERATION)?)?;

        let account_binding = bytes_field(map, FIELD_ACCOUNT_BINDING)?;

        let challenge = Self {
            windows_device_id,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            operation,
            account_binding,
        };

        challenge.validate()?;
        Ok(challenge)
    }
}

pub fn encode_login_challenge(challenge: &LoginChallenge) -> Result<Vec<u8>, ProtocolError> {
    encode(&challenge.to_cbor()?)
}

pub fn decode_login_challenge(data: &[u8]) -> Result<LoginChallenge, ProtocolError> {
    let value = decode(data)?;
    LoginChallenge::from_cbor(&value)
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
