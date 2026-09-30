//! Distinct, fixed-layout approval transcript for opening one encrypted file.
//! Transport and single-use redemption are intentionally outside this module.

use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::cbor::{self, CborValue};
use crate::error::ProtocolError;
use crate::types::{DeviceId, MAX_LOGIN_SESSION_TTL_MS, Nonce, SessionId};

const DOMAIN: &[u8] = b"PHONEKEY-FILE-OPEN-SIGNATURE-V2\x00";
const WRAP_LEN: usize = 129;
const RETURN_PUBLIC_LEN: usize = 65;
const RETURN_RECORD_LEN: usize = 129;
pub const MESSAGE_TYPE_FILE_OPEN_CHALLENGE: u64 = 20;
pub const MESSAGE_TYPE_FILE_OPEN_PROOF: u64 = 21;

fn number(map: &BTreeMap<u16, CborValue>, field: u16) -> Result<u64, ProtocolError> {
    match map.get(&field) {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        Some(_) => Err(ProtocolError::InvalidFieldType(field)),
        None => Err(ProtocolError::MissingField(field)),
    }
}

fn bytes<const N: usize>(
    map: &BTreeMap<u16, CborValue>,
    field: u16,
) -> Result<[u8; N], ProtocolError> {
    match map.get(&field) {
        Some(CborValue::Bytes(value)) => value
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidFieldLength(field)),
        Some(_) => Err(ProtocolError::InvalidFieldType(field)),
        None => Err(ProtocolError::MissingField(field)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpenChallenge {
    pub windows_device_id: DeviceId,
    pub phone_device_id: DeviceId,
    pub session_id: SessionId,
    pub nonce: Nonce,
    /// SHA-256 of the complete authenticated encrypted-file envelope.
    pub envelope_sha256: [u8; 32],
    pub phone_wrap: [u8; WRAP_LEN],
    pub return_public_sec1: [u8; RETURN_PUBLIC_LEN],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpenProof {
    pub phone_device_id: DeviceId,
    pub session_id: SessionId,
    pub signature: [u8; 64],
    pub encrypted_file_key: [u8; RETURN_RECORD_LEN],
}

/// One-use approval gate. The service must construct it from protected trust
/// state and rehash the encrypted file immediately before redemption.
pub struct FileOpenSession {
    challenge: FileOpenChallenge,
    trusted_public_key: Vec<u8>,
    deadline: Instant,
    consumed: bool,
}

impl FileOpenSession {
    pub fn new(
        challenge: FileOpenChallenge,
        trusted_public_key: Vec<u8>,
        started: Instant,
    ) -> Result<Self, ProtocolError> {
        challenge.transcript()?;
        VerifyingKey::from_sec1_bytes(&trusted_public_key)
            .map_err(|_| ProtocolError::InvalidCryptoKey)?;
        let lifetime = challenge.expires_at_ms - challenge.issued_at_ms;
        let deadline = started
            .checked_add(Duration::from_millis(lifetime))
            .ok_or(ProtocolError::SessionLifetimeTooLong)?;
        Ok(Self {
            challenge,
            trusted_public_key,
            deadline,
            consumed: false,
        })
    }

    pub fn redeem(
        &mut self,
        proof: &FileOpenProof,
        current_envelope_sha256: &[u8; 32],
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<(), ProtocolError> {
        if self.consumed {
            return Err(ProtocolError::SessionAlreadyConsumed);
        }
        if now_ms < self.challenge.issued_at_ms {
            return Err(ProtocolError::SessionNotYetValid);
        }
        if now_ms >= self.challenge.expires_at_ms || monotonic_now >= self.deadline {
            return Err(ProtocolError::SessionExpired);
        }
        if current_envelope_sha256 != &self.challenge.envelope_sha256 {
            return Err(ProtocolError::SessionBindingMismatch);
        }
        proof.verify_for(&self.challenge, &self.trusted_public_key)?;
        self.consumed = true;
        Ok(())
    }
}

impl FileOpenProof {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut map = BTreeMap::new();
        map.insert(1, CborValue::Unsigned(1));
        map.insert(2, CborValue::Unsigned(MESSAGE_TYPE_FILE_OPEN_PROOF));
        map.insert(3, CborValue::Bytes(self.phone_device_id.0.to_vec()));
        map.insert(4, CborValue::Bytes(self.session_id.0.to_vec()));
        map.insert(5, CborValue::Bytes(self.signature.to_vec()));
        map.insert(6, CborValue::Bytes(self.encrypted_file_key.to_vec()));
        cbor::encode(&CborValue::Map(map))
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtocolError> {
        let CborValue::Map(map) = cbor::decode(encoded)? else {
            return Err(ProtocolError::Malformed);
        };
        if map.len() != 6 {
            return Err(ProtocolError::Malformed);
        }
        if number(&map, 1)? != 1 {
            return Err(ProtocolError::InvalidFieldValue(1));
        }
        if number(&map, 2)? != MESSAGE_TYPE_FILE_OPEN_PROOF {
            return Err(ProtocolError::InvalidFieldValue(2));
        }
        Ok(Self {
            phone_device_id: DeviceId(bytes(&map, 3)?),
            session_id: SessionId(bytes(&map, 4)?),
            signature: bytes(&map, 5)?,
            encrypted_file_key: bytes(&map, 6)?,
        })
    }

    pub fn verify_for(
        &self,
        challenge: &FileOpenChallenge,
        public_key_sec1: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.phone_device_id != challenge.phone_device_id
            || self.session_id != challenge.session_id
        {
            return Err(ProtocolError::ProofBindingMismatch);
        }
        verify_file_open(
            public_key_sec1,
            challenge,
            &self.encrypted_file_key,
            &self.signature,
        )
    }
}

impl FileOpenChallenge {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.transcript()?;
        let mut map = BTreeMap::new();
        map.insert(1, CborValue::Unsigned(1));
        map.insert(2, CborValue::Unsigned(MESSAGE_TYPE_FILE_OPEN_CHALLENGE));
        map.insert(3, CborValue::Bytes(self.windows_device_id.0.to_vec()));
        map.insert(4, CborValue::Bytes(self.phone_device_id.0.to_vec()));
        map.insert(5, CborValue::Bytes(self.session_id.0.to_vec()));
        map.insert(6, CborValue::Bytes(self.nonce.0.to_vec()));
        map.insert(7, CborValue::Bytes(self.envelope_sha256.to_vec()));
        map.insert(8, CborValue::Unsigned(self.issued_at_ms));
        map.insert(9, CborValue::Unsigned(self.expires_at_ms));
        map.insert(10, CborValue::Bytes(self.phone_wrap.to_vec()));
        map.insert(11, CborValue::Bytes(self.return_public_sec1.to_vec()));
        cbor::encode(&CborValue::Map(map))
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtocolError> {
        let CborValue::Map(map) = cbor::decode(encoded)? else {
            return Err(ProtocolError::Malformed);
        };
        if map.len() != 11 {
            return Err(ProtocolError::Malformed);
        }
        if number(&map, 1)? != 1 {
            return Err(ProtocolError::InvalidFieldValue(1));
        }
        if number(&map, 2)? != MESSAGE_TYPE_FILE_OPEN_CHALLENGE {
            return Err(ProtocolError::InvalidFieldValue(2));
        }
        let challenge = Self {
            windows_device_id: DeviceId(bytes(&map, 3)?),
            phone_device_id: DeviceId(bytes(&map, 4)?),
            session_id: SessionId(bytes(&map, 5)?),
            nonce: Nonce(bytes(&map, 6)?),
            envelope_sha256: bytes(&map, 7)?,
            issued_at_ms: number(&map, 8)?,
            expires_at_ms: number(&map, 9)?,
            phone_wrap: bytes(&map, 10)?,
            return_public_sec1: bytes(&map, 11)?,
        };
        challenge.transcript()?;
        Ok(challenge)
    }

    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(ProtocolError::SessionExpired);
        }
        if self.expires_at_ms - self.issued_at_ms > MAX_LOGIN_SESSION_TTL_MS {
            return Err(ProtocolError::SessionLifetimeTooLong);
        }
        if &self.phone_wrap[..4] != b"PKW1"
            || self.return_public_sec1[0] != 4
            || p256::PublicKey::from_sec1_bytes(&self.return_public_sec1).is_err()
        {
            return Err(ProtocolError::InvalidCryptoKey);
        }
        let mut out = Vec::with_capacity(
            DOMAIN.len() + 16 + 16 + 16 + 32 + 32 + 8 + 8 + WRAP_LEN + RETURN_PUBLIC_LEN,
        );
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.windows_device_id.0);
        out.extend_from_slice(&self.phone_device_id.0);
        out.extend_from_slice(&self.session_id.0);
        out.extend_from_slice(&self.nonce.0);
        out.extend_from_slice(&self.envelope_sha256);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.phone_wrap);
        out.extend_from_slice(&self.return_public_sec1);
        Ok(out)
    }

    /// The QR commits to every field in the signed BLE challenge. Any later
    /// challenge revision must use a new QR prefix and the revised transcript.
    pub fn qr_payload(&self) -> Result<String, ProtocolError> {
        let digest = Sha256::digest(self.transcript()?);
        Ok(format!(
            "PKF3|{}|{}|{}|{:016x}",
            hex_lower(&self.windows_device_id.0),
            hex_lower(&self.session_id.0),
            hex_lower(&digest),
            self.expires_at_ms
        ))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

pub fn sign_file_open(
    key: &SigningKey,
    challenge: &FileOpenChallenge,
    encrypted_file_key: &[u8; RETURN_RECORD_LEN],
) -> Result<[u8; 64], ProtocolError> {
    if &encrypted_file_key[..4] != b"PKR1" {
        return Err(ProtocolError::InvalidCryptoKey);
    }
    let mut transcript = challenge.transcript()?;
    transcript.extend_from_slice(encrypted_file_key);
    let signature: Signature = key.sign(&transcript);
    let signature = signature.normalize_s();
    let mut output = [0u8; 64];
    output.copy_from_slice(signature.to_bytes().as_ref());
    Ok(output)
}

pub fn verify_file_open(
    public_key_sec1: &[u8],
    challenge: &FileOpenChallenge,
    encrypted_file_key: &[u8; RETURN_RECORD_LEN],
    signature_bytes: &[u8],
) -> Result<(), ProtocolError> {
    let key = VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| ProtocolError::InvalidCryptoKey)?;
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| ProtocolError::InvalidSignature)?;
    if signature.normalize_s() != signature {
        return Err(ProtocolError::InvalidSignature);
    }
    if &encrypted_file_key[..4] != b"PKR1" {
        return Err(ProtocolError::InvalidCryptoKey);
    }
    let mut transcript = challenge.transcript()?;
    transcript.extend_from_slice(encrypted_file_key);
    key.verify(&transcript, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{public_key_sec1, sign_login_challenge};
    use crate::messages::{LoginChallenge, LoginOperation};

    fn challenge() -> FileOpenChallenge {
        let mut phone_wrap = [0u8; WRAP_LEN];
        phone_wrap[..4].copy_from_slice(b"PKW1");
        let return_public_sec1: [u8; RETURN_PUBLIC_LEN] =
            SigningKey::from_bytes((&[7u8; 32]).into())
                .unwrap()
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .unwrap();
        FileOpenChallenge {
            windows_device_id: DeviceId([1; 16]),
            phone_device_id: DeviceId([2; 16]),
            session_id: SessionId([3; 16]),
            nonce: Nonce([4; 32]),
            envelope_sha256: [5; 32],
            phone_wrap,
            return_public_sec1,
            issued_at_ms: 1000,
            expires_at_ms: 61_000,
        }
    }

    fn return_record() -> [u8; RETURN_RECORD_LEN] {
        let mut record = [7u8; RETURN_RECORD_LEN];
        record[..4].copy_from_slice(b"PKR1");
        record
    }

    #[test]
    fn signature_is_bound_to_file_phone_and_expiry() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let public = public_key_sec1(&key);
        let original = challenge();
        let signature = sign_file_open(&key, &original, &return_record()).unwrap();
        verify_file_open(&public, &original, &return_record(), &signature).unwrap();
        let mut altered = original.clone();
        altered.envelope_sha256[0] ^= 1;
        assert_eq!(
            verify_file_open(&public, &altered, &return_record(), &signature),
            Err(ProtocolError::InvalidSignature)
        );
        altered = original.clone();
        altered.phone_device_id.0[0] ^= 1;
        assert_eq!(
            verify_file_open(&public, &altered, &return_record(), &signature),
            Err(ProtocolError::InvalidSignature)
        );
        altered = original.clone();
        altered.expires_at_ms -= 1;
        assert_eq!(
            verify_file_open(&public, &altered, &return_record(), &signature),
            Err(ProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn login_signature_cannot_approve_a_file() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let file = challenge();
        let login = LoginChallenge {
            windows_device_id: file.windows_device_id,
            session_id: file.session_id,
            nonce: file.nonce,
            issued_at_ms: file.issued_at_ms,
            expires_at_ms: file.expires_at_ms,
            operation: LoginOperation::Unlock,
            account_binding: vec![8; 32],
        };
        let signature = sign_login_challenge(&key, &login).unwrap();
        assert_eq!(
            verify_file_open(&public_key_sec1(&key), &file, &return_record(), &signature),
            Err(ProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn invalid_lifetimes_are_rejected() {
        let mut file = challenge();
        file.expires_at_ms = file.issued_at_ms;
        assert_eq!(file.transcript(), Err(ProtocolError::SessionExpired));
        file.expires_at_ms = file.issued_at_ms + MAX_LOGIN_SESSION_TTL_MS + 1;
        assert_eq!(
            file.transcript(),
            Err(ProtocolError::SessionLifetimeTooLong)
        );
    }

    #[test]
    fn canonical_message_round_trips_and_rejects_extra_fields() {
        let original = challenge();
        let encoded = original.encode().unwrap();
        let expected = format!(
            "ab010102140350{}0450{}0550{}065820{}075820{}081903e80919ee480a5881{}0b5841{}",
            "01".repeat(16),
            "02".repeat(16),
            "03".repeat(16),
            "04".repeat(32),
            "05".repeat(32),
            hex::encode(original.phone_wrap),
            hex::encode(original.return_public_sec1)
        );
        assert_eq!(hex::encode(&encoded), expected);
        assert_eq!(FileOpenChallenge::decode(&encoded).unwrap(), original);
        let CborValue::Map(mut map) = cbor::decode(&encoded).unwrap() else {
            unreachable!()
        };
        map.insert(12, CborValue::Unsigned(1));
        assert_eq!(
            FileOpenChallenge::decode(&cbor::encode(&CborValue::Map(map)).unwrap()),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn proof_round_trips_and_binds_phone_and_session() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let original = challenge();
        let proof = FileOpenProof {
            phone_device_id: original.phone_device_id,
            session_id: original.session_id,
            signature: sign_file_open(&key, &original, &return_record()).unwrap(),
            encrypted_file_key: return_record(),
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(FileOpenProof::decode(&encoded).unwrap(), proof);
        proof.verify_for(&original, &public_key_sec1(&key)).unwrap();
        let mut changed = proof.clone();
        changed.session_id.0[0] ^= 1;
        assert_eq!(
            changed.verify_for(&original, &public_key_sec1(&key)),
            Err(ProtocolError::ProofBindingMismatch)
        );
        changed = proof.clone();
        changed.encrypted_file_key[100] ^= 1;
        assert_eq!(
            changed.verify_for(&original, &public_key_sec1(&key)),
            Err(ProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn proof_encoding_matches_android_layout() {
        let proof = FileOpenProof {
            phone_device_id: DeviceId([2; 16]),
            session_id: SessionId([3; 16]),
            signature: [7; 64],
            encrypted_file_key: return_record(),
        };
        let expected = format!(
            "a6010102150350{}0450{}055840{}065881{}",
            "02".repeat(16),
            "03".repeat(16),
            "07".repeat(64),
            hex::encode(return_record())
        );
        assert_eq!(hex::encode(proof.encode().unwrap()), expected);
    }

    #[test]
    fn qr_matches_android_file_scan_layout() {
        let digest = Sha256::digest(challenge().transcript().unwrap());
        assert_eq!(
            hex::encode(digest),
            "c2de276468e4123408ffdd18ab627c2ff710a339ccacdb953d4b445f776d09bb"
        );
        let expected = format!(
            "PKF3|{}|{}|{}|000000000000ee48",
            "01".repeat(16),
            "03".repeat(16),
            hex::encode(digest)
        );
        assert_eq!(challenge().qr_payload().unwrap(), expected);
        assert_eq!(expected.len(), 152);
    }

    #[test]
    fn qr_changes_for_every_signed_challenge_field() {
        let original = challenge();
        let qr = original.qr_payload().unwrap();
        let mut changed = original.clone();
        changed.phone_device_id.0[0] ^= 1;
        assert_ne!(changed.qr_payload().unwrap(), qr);
        changed = original.clone();
        changed.nonce.0[0] ^= 1;
        assert_ne!(changed.qr_payload().unwrap(), qr);
        changed = original.clone();
        changed.envelope_sha256[0] ^= 1;
        assert_ne!(changed.qr_payload().unwrap(), qr);
        changed = original.clone();
        changed.phone_wrap[50] ^= 1;
        assert_ne!(changed.qr_payload().unwrap(), qr);
        changed = original.clone();
        changed.return_public_sec1 = SigningKey::from_bytes((&[8u8; 32]).into())
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_ne!(changed.qr_payload().unwrap(), qr);
    }

    #[test]
    fn file_open_is_single_use_and_bound_to_current_ciphertext() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let original = challenge();
        let proof = FileOpenProof {
            phone_device_id: original.phone_device_id,
            session_id: original.session_id,
            signature: sign_file_open(&key, &original, &return_record()).unwrap(),
            encrypted_file_key: return_record(),
        };
        let start = Instant::now();
        let mut session =
            FileOpenSession::new(original.clone(), public_key_sec1(&key).to_vec(), start).unwrap();
        assert_eq!(
            session.redeem(&proof, &[9; 32], 2000, start),
            Err(ProtocolError::SessionBindingMismatch)
        );
        session
            .redeem(&proof, &original.envelope_sha256, 2000, start)
            .unwrap();
        assert_eq!(
            session.redeem(&proof, &original.envelope_sha256, 2001, start),
            Err(ProtocolError::SessionAlreadyConsumed)
        );
    }

    #[test]
    fn invalid_proof_does_not_consume_and_expiry_rejects() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let original = challenge();
        let mut proof = FileOpenProof {
            phone_device_id: original.phone_device_id,
            session_id: original.session_id,
            signature: sign_file_open(&key, &original, &return_record()).unwrap(),
            encrypted_file_key: return_record(),
        };
        let start = Instant::now();
        let mut session =
            FileOpenSession::new(original.clone(), public_key_sec1(&key).to_vec(), start).unwrap();
        proof.signature[0] ^= 1;
        assert_eq!(
            session.redeem(&proof, &original.envelope_sha256, 2000, start),
            Err(ProtocolError::InvalidSignature)
        );
        proof.signature[0] ^= 1;
        assert_eq!(
            session.redeem(&proof, &original.envelope_sha256, 61_000, start),
            Err(ProtocolError::SessionExpired)
        );
        assert_eq!(
            session.redeem(
                &proof,
                &original.envelope_sha256,
                2000,
                start + Duration::from_millis(60_000)
            ),
            Err(ProtocolError::SessionExpired)
        );
        session
            .redeem(&proof, &original.envelope_sha256, 2000, start)
            .unwrap();
    }
}
