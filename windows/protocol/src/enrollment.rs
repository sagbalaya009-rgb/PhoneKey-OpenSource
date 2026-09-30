use std::collections::BTreeMap;

use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

use crate::cbor::{CborValue, decode, encode};
use crate::error::ProtocolError;
use crate::messages::PROTOCOL_VERSION;
use crate::types::{DEVICE_ID_LEN, DeviceId, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId};

pub const MESSAGE_TYPE_ENROLLMENT_CHALLENGE: u64 = 10;
pub const MESSAGE_TYPE_ENROLLMENT_PROOF: u64 = 11;

pub const ENROLLMENT_SIGNATURE_LEN: usize = 64;
pub const P256_PUBLIC_KEY_LEN: usize = 65;
pub const MAX_ENROLLMENT_TTL_MS: u64 = 185_000;

const FIELD_VERSION: u16 = 1;
const FIELD_MESSAGE_TYPE: u16 = 2;

/*
 * EnrollmentChallenge fields
 */
const FIELD_WINDOWS_DEVICE_ID: u16 = 3;
const FIELD_ENROLLMENT_ID: u16 = 4;
const FIELD_NONCE: u16 = 5;
const FIELD_ISSUED_AT_MS: u16 = 6;
const FIELD_EXPIRES_AT_MS: u16 = 7;

/*
 * EnrollmentProof fields
 */
const FIELD_ANDROID_DEVICE_ID: u16 = 3;
const FIELD_PROOF_ENROLLMENT_ID: u16 = 4;
const FIELD_PUBLIC_KEY: u16 = 5;
const FIELD_SIGNATURE: u16 = 6;

const ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"PHONEKEY-ENROLLMENT-SIGNATURE-V1\0";

const PAIRING_CODE_DOMAIN: &[u8] = b"PHONEKEY-PAIRING-CODE-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentChallenge {
    pub windows_device_id: DeviceId,
    pub enrollment_id: SessionId,
    pub nonce: Nonce,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl EnrollmentChallenge {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(ProtocolError::InvalidFieldValue(FIELD_EXPIRES_AT_MS));
        }

        let ttl = self.expires_at_ms - self.issued_at_ms;

        if ttl > MAX_ENROLLMENT_TTL_MS {
            return Err(ProtocolError::InvalidFieldValue(FIELD_EXPIRES_AT_MS));
        }

        Ok(())
    }

    pub fn to_cbor(&self) -> Result<CborValue, ProtocolError> {
        self.validate()?;

        let mut map = BTreeMap::new();

        map.insert(FIELD_VERSION, CborValue::Unsigned(PROTOCOL_VERSION));

        map.insert(
            FIELD_MESSAGE_TYPE,
            CborValue::Unsigned(MESSAGE_TYPE_ENROLLMENT_CHALLENGE),
        );

        map.insert(
            FIELD_WINDOWS_DEVICE_ID,
            CborValue::Bytes(self.windows_device_id.0.to_vec()),
        );

        map.insert(
            FIELD_ENROLLMENT_ID,
            CborValue::Bytes(self.enrollment_id.0.to_vec()),
        );

        map.insert(FIELD_NONCE, CborValue::Bytes(self.nonce.0.to_vec()));

        map.insert(FIELD_ISSUED_AT_MS, CborValue::Unsigned(self.issued_at_ms));

        map.insert(FIELD_EXPIRES_AT_MS, CborValue::Unsigned(self.expires_at_ms));

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
                    | FIELD_ENROLLMENT_ID
                    | FIELD_NONCE
                    | FIELD_ISSUED_AT_MS
                    | FIELD_EXPIRES_AT_MS
            ) {
                return Err(ProtocolError::UnexpectedField(*key));
            }
        }

        if unsigned_field(map, FIELD_VERSION)? != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidFieldValue(FIELD_VERSION));
        }

        if unsigned_field(map, FIELD_MESSAGE_TYPE)? != MESSAGE_TYPE_ENROLLMENT_CHALLENGE {
            return Err(ProtocolError::InvalidFieldValue(FIELD_MESSAGE_TYPE));
        }

        let challenge = Self {
            windows_device_id: DeviceId(fixed_bytes::<DEVICE_ID_LEN>(
                map,
                FIELD_WINDOWS_DEVICE_ID,
            )?),

            enrollment_id: SessionId(fixed_bytes::<SESSION_ID_LEN>(map, FIELD_ENROLLMENT_ID)?),

            nonce: Nonce(fixed_bytes::<NONCE_LEN>(map, FIELD_NONCE)?),

            issued_at_ms: unsigned_field(map, FIELD_ISSUED_AT_MS)?,

            expires_at_ms: unsigned_field(map, FIELD_EXPIRES_AT_MS)?,
        };

        challenge.validate()?;

        Ok(challenge)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentProof {
    pub android_device_id: DeviceId,
    pub enrollment_id: SessionId,
    pub public_key_sec1: [u8; P256_PUBLIC_KEY_LEN],
    pub signature: [u8; ENROLLMENT_SIGNATURE_LEN],
}

impl EnrollmentProof {
    pub fn to_cbor(&self) -> CborValue {
        let mut map = BTreeMap::new();

        map.insert(FIELD_VERSION, CborValue::Unsigned(PROTOCOL_VERSION));

        map.insert(
            FIELD_MESSAGE_TYPE,
            CborValue::Unsigned(MESSAGE_TYPE_ENROLLMENT_PROOF),
        );

        map.insert(
            FIELD_ANDROID_DEVICE_ID,
            CborValue::Bytes(self.android_device_id.0.to_vec()),
        );

        map.insert(
            FIELD_PROOF_ENROLLMENT_ID,
            CborValue::Bytes(self.enrollment_id.0.to_vec()),
        );

        map.insert(
            FIELD_PUBLIC_KEY,
            CborValue::Bytes(self.public_key_sec1.to_vec()),
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
                    | FIELD_PROOF_ENROLLMENT_ID
                    | FIELD_PUBLIC_KEY
                    | FIELD_SIGNATURE
            ) {
                return Err(ProtocolError::UnexpectedField(*key));
            }
        }

        if unsigned_field(map, FIELD_VERSION)? != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidFieldValue(FIELD_VERSION));
        }

        if unsigned_field(map, FIELD_MESSAGE_TYPE)? != MESSAGE_TYPE_ENROLLMENT_PROOF {
            return Err(ProtocolError::InvalidFieldValue(FIELD_MESSAGE_TYPE));
        }

        Ok(Self {
            android_device_id: DeviceId(fixed_bytes::<DEVICE_ID_LEN>(
                map,
                FIELD_ANDROID_DEVICE_ID,
            )?),

            enrollment_id: SessionId(fixed_bytes::<SESSION_ID_LEN>(
                map,
                FIELD_PROOF_ENROLLMENT_ID,
            )?),

            public_key_sec1: fixed_bytes::<P256_PUBLIC_KEY_LEN>(map, FIELD_PUBLIC_KEY)?,

            signature: fixed_bytes::<ENROLLMENT_SIGNATURE_LEN>(map, FIELD_SIGNATURE)?,
        })
    }
}

pub fn encode_enrollment_challenge(
    challenge: &EnrollmentChallenge,
) -> Result<Vec<u8>, ProtocolError> {
    encode(&challenge.to_cbor()?)
}

pub fn decode_enrollment_challenge(data: &[u8]) -> Result<EnrollmentChallenge, ProtocolError> {
    let value = decode(data)?;

    EnrollmentChallenge::from_cbor(&value)
}

pub fn encode_enrollment_proof(proof: &EnrollmentProof) -> Result<Vec<u8>, ProtocolError> {
    encode(&proof.to_cbor())
}

pub fn decode_enrollment_proof(data: &[u8]) -> Result<EnrollmentProof, ProtocolError> {
    let value = decode(data)?;

    EnrollmentProof::from_cbor(&value)
}

pub fn build_enrollment_transcript(
    challenge: &EnrollmentChallenge,
    android_device_id: &DeviceId,
    public_key_sec1: &[u8; P256_PUBLIC_KEY_LEN],
) -> Result<Vec<u8>, ProtocolError> {
    let challenge_bytes = encode_enrollment_challenge(challenge)?;

    let mut transcript = Vec::with_capacity(
        ENROLLMENT_SIGNATURE_DOMAIN.len()
            + challenge_bytes.len()
            + DEVICE_ID_LEN
            + P256_PUBLIC_KEY_LEN,
    );

    transcript.extend_from_slice(ENROLLMENT_SIGNATURE_DOMAIN);

    transcript.extend_from_slice(&challenge_bytes);

    transcript.extend_from_slice(&android_device_id.0);

    transcript.extend_from_slice(public_key_sec1);

    Ok(transcript)
}

pub fn create_enrollment_proof(
    signing_key: &SigningKey,
    android_device_id: DeviceId,
    challenge: &EnrollmentChallenge,
) -> Result<EnrollmentProof, ProtocolError> {
    let public_key = signing_key.verifying_key().to_sec1_point(false);

    let public_key_bytes = public_key.as_bytes();

    if public_key_bytes.len() != P256_PUBLIC_KEY_LEN {
        return Err(ProtocolError::InvalidCryptoKey);
    }

    let mut public_key_sec1 = [0u8; P256_PUBLIC_KEY_LEN];

    public_key_sec1.copy_from_slice(public_key_bytes);

    let transcript = build_enrollment_transcript(challenge, &android_device_id, &public_key_sec1)?;

    let signature: Signature = signing_key.sign(&transcript);

    let signature = signature.normalize_s();

    let mut raw_signature = [0u8; ENROLLMENT_SIGNATURE_LEN];

    raw_signature.copy_from_slice(&signature.to_bytes());

    Ok(EnrollmentProof {
        android_device_id,
        enrollment_id: challenge.enrollment_id,
        public_key_sec1,
        signature: raw_signature,
    })
}

pub fn verify_enrollment_proof(
    proof: &EnrollmentProof,
    challenge: &EnrollmentChallenge,
) -> Result<(), ProtocolError> {
    if proof.enrollment_id != challenge.enrollment_id {
        return Err(ProtocolError::ProofBindingMismatch);
    }

    if proof.android_device_id.0.iter().all(|value| *value == 0) {
        return Err(ProtocolError::InvalidFieldValue(FIELD_ANDROID_DEVICE_ID));
    }

    if proof.public_key_sec1[0] != 0x04 {
        return Err(ProtocolError::InvalidCryptoKey);
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(&proof.public_key_sec1)
        .map_err(|_| ProtocolError::InvalidCryptoKey)?;

    let signature =
        Signature::from_slice(&proof.signature).map_err(|_| ProtocolError::InvalidSignature)?;

    let normalized = signature.normalize_s();

    if normalized != signature {
        return Err(ProtocolError::InvalidSignature);
    }

    let transcript =
        build_enrollment_transcript(challenge, &proof.android_device_id, &proof.public_key_sec1)?;

    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

pub fn derive_pairing_code(
    challenge: &EnrollmentChallenge,
    proof: &EnrollmentProof,
) -> Result<u32, ProtocolError> {
    use sha2::{Digest, Sha256};

    let challenge_bytes = encode_enrollment_challenge(challenge)?;

    let proof_bytes = encode_enrollment_proof(proof)?;

    let mut hasher = Sha256::new();

    hasher.update(PAIRING_CODE_DOMAIN);

    hasher.update(challenge_bytes);

    hasher.update(proof_bytes);

    let digest = hasher.finalize();

    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);

    Ok(value % 1_000_000)
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
