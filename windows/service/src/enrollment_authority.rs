use crate::trust_store::{self, TrustedPhone};

use phonekey_protocol::enrollment::{
    EnrollmentChallenge, EnrollmentProof, decode_enrollment_proof, derive_pairing_code,
    encode_enrollment_challenge, verify_enrollment_proof,
};

use phonekey_protocol::error::ProtocolError;

use phonekey_protocol::types::{DeviceId, Nonce, SessionId};

use rand::RngCore as _;

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;

// The protocol caps the signed interval at 60 seconds. Reserve five seconds
// of that interval for a phone clock that trails Windows.
// Human comparison of two pairing codes needs time for UAC and accessibility.
// The five-second issued-at allowance is included in the protocol's 185s cap.
const ENROLLMENT_TTL_MS: u64 = 180_000;
const CLOCK_SKEW_ALLOWANCE_MS: u64 = 5_000;

const MAX_WINDOWS_SID_LENGTH: usize = 184;

#[derive(Debug, Error)]
pub enum EnrollmentAuthorityError {
    #[error("a PhoneKey enrollment is already pending")]
    AlreadyPending,

    #[error("a privileged PhoneKey device is already enrolled")]
    AlreadyEnrolled,

    #[error("no PhoneKey enrollment is pending")]
    NoPendingEnrollment,

    #[error("the enrollment has expired")]
    Expired,

    #[error("the enrollment proof has already been accepted")]
    ProofAlreadySubmitted,

    #[error("pairing confirmation is not ready")]
    PairingNotReady,

    #[error("pairing code confirmation failed")]
    PairingCodeMismatch,

    #[error("enrollment transaction belongs to a different administrator")]
    CallerMismatch,

    #[error("enrollment initiator SID is invalid")]
    InvalidInitiatorSid,

    #[error("system or monotonic time overflow while creating enrollment")]
    ClockOverflow,

    #[error("PhoneKey protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("PhoneKey privileged trust error: {0}")]
    Trust(#[from] io::Error),
}

struct VerifiedEnrollment {
    proof: EnrollmentProof,

    pairing_code: u32,
}

struct PendingEnrollment {
    challenge: EnrollmentChallenge,

    created_at_ms: u64,

    initiator_sid: String,

    monotonic_deadline: Instant,

    verified: Option<VerifiedEnrollment>,
}

pub struct EnrollmentAuthority {
    trust_path: PathBuf,

    pending: Option<PendingEnrollment>,
}

impl EnrollmentAuthority {
    pub fn production() -> Result<Self, EnrollmentAuthorityError> {
        Ok(Self {
            trust_path: trust_store::trusted_phone_path()?,

            pending: None,
        })
    }

    pub fn from_trust_path(trust_path: impl Into<PathBuf>) -> Self {
        Self {
            trust_path: trust_path.into(),

            pending: None,
        }
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn begin(
        &mut self,
        windows_device_id: DeviceId,
        initiator_sid: &str,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<Vec<u8>, EnrollmentAuthorityError> {
        if self.pending.is_some() {
            return Err(EnrollmentAuthorityError::AlreadyPending);
        }

        validate_initiator_sid(initiator_sid)?;

        if trust_store::load_at(&self.trust_path)?.is_some() {
            return Err(EnrollmentAuthorityError::AlreadyEnrolled);
        }

        let expires_at_ms = now_ms
            .checked_add(ENROLLMENT_TTL_MS)
            .ok_or(EnrollmentAuthorityError::ClockOverflow)?;

        let monotonic_deadline = monotonic_now
            .checked_add(Duration::from_millis(ENROLLMENT_TTL_MS))
            .ok_or(EnrollmentAuthorityError::ClockOverflow)?;

        let enrollment_id = random_session_id();

        let nonce = random_nonce();

        let challenge = EnrollmentChallenge {
            windows_device_id,

            enrollment_id,

            nonce,

            issued_at_ms: now_ms.saturating_sub(CLOCK_SKEW_ALLOWANCE_MS),

            expires_at_ms,
        };

        let encoded = encode_enrollment_challenge(&challenge)?;

        self.pending = Some(PendingEnrollment {
            challenge,

            created_at_ms: now_ms,

            initiator_sid: initiator_sid.to_owned(),

            monotonic_deadline,

            verified: None,
        });

        Ok(encoded)
    }

    pub fn submit_proof(
        &mut self,
        proof_bytes: &[u8],
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<u32, EnrollmentAuthorityError> {
        let expired = match self.pending.as_ref() {
            Some(pending) => enrollment_expired(pending, now_ms, monotonic_now),

            None => {
                return Err(EnrollmentAuthorityError::NoPendingEnrollment);
            }
        };

        if expired {
            self.pending = None;

            return Err(EnrollmentAuthorityError::Expired);
        }

        let pending = self
            .pending
            .as_mut()
            .ok_or(EnrollmentAuthorityError::NoPendingEnrollment)?;

        if pending.verified.is_some() {
            return Err(EnrollmentAuthorityError::ProofAlreadySubmitted);
        }

        /*
         * SUBMIT_PROOF deliberately remains an untrusted-courier
         * operation.
         */
        let proof = decode_enrollment_proof(proof_bytes)?;

        verify_enrollment_proof(&proof, &pending.challenge)?;

        let pairing_code = derive_pairing_code(&pending.challenge, &proof)?;

        pending.verified = Some(VerifiedEnrollment {
            proof,

            pairing_code,
        });

        Ok(pairing_code)
    }

    pub fn pairing_code_for_initiator(
        &mut self,
        caller_sid: &str,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<u32, EnrollmentAuthorityError> {
        validate_initiator_sid(caller_sid)?;

        let pending = self
            .pending
            .as_ref()
            .ok_or(EnrollmentAuthorityError::NoPendingEnrollment)?;

        /*
         * Caller ownership is checked before expiry handling.
         *
         * A different administrator must not be able to inspect,
         * expire, consume, or otherwise mutate another
         * administrator's enrollment transaction.
         */
        if pending.initiator_sid != caller_sid {
            return Err(EnrollmentAuthorityError::CallerMismatch);
        }

        let expired = enrollment_expired(pending, now_ms, monotonic_now);

        if expired {
            self.pending = None;

            return Err(EnrollmentAuthorityError::Expired);
        }

        let pending = self
            .pending
            .as_ref()
            .ok_or(EnrollmentAuthorityError::NoPendingEnrollment)?;

        let verified = pending
            .verified
            .as_ref()
            .ok_or(EnrollmentAuthorityError::PairingNotReady)?;

        Ok(verified.pairing_code)
    }

    pub fn confirm(
        &mut self,
        submitted_code: u32,
        caller_sid: &str,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<(), EnrollmentAuthorityError> {
        validate_initiator_sid(caller_sid)?;

        let pending = self
            .pending
            .as_ref()
            .ok_or(EnrollmentAuthorityError::NoPendingEnrollment)?;

        if pending.initiator_sid != caller_sid {
            return Err(EnrollmentAuthorityError::CallerMismatch);
        }

        if enrollment_expired(pending, now_ms, monotonic_now) {
            self.pending = None;

            return Err(EnrollmentAuthorityError::Expired);
        }

        let (expected_code, proof) = {
            let pending = self
                .pending
                .as_ref()
                .ok_or(EnrollmentAuthorityError::NoPendingEnrollment)?;

            let verified = pending
                .verified
                .as_ref()
                .ok_or(EnrollmentAuthorityError::PairingNotReady)?;

            (verified.pairing_code, verified.proof.clone())
        };

        /*
         * One wrong code destroys the transaction.
         */
        if submitted_code != expected_code {
            self.pending = None;

            return Err(EnrollmentAuthorityError::PairingCodeMismatch);
        }

        let trusted_phone = TrustedPhone {
            android_device_id: proof.android_device_id,

            public_key_sec1: proof.public_key_sec1,
        };

        /*
         * Consume the transaction once persistence is attempted.
         */
        let persistence = trust_store::enroll_at(&self.trust_path, &trusted_phone);

        self.pending = None;

        persistence?;

        Ok(())
    }

    pub fn cancel(&mut self, caller_sid: &str) -> Result<(), EnrollmentAuthorityError> {
        validate_initiator_sid(caller_sid)?;

        let pending = self
            .pending
            .as_ref()
            .ok_or(EnrollmentAuthorityError::NoPendingEnrollment)?;

        if pending.initiator_sid != caller_sid {
            return Err(EnrollmentAuthorityError::CallerMismatch);
        }

        self.pending = None;

        Ok(())
    }

    pub fn trust_path(&self) -> &Path {
        &self.trust_path
    }
}

fn enrollment_expired(pending: &PendingEnrollment, now_ms: u64, monotonic_now: Instant) -> bool {
    now_ms < pending.created_at_ms
        || now_ms >= pending.challenge.expires_at_ms
        || monotonic_now >= pending.monotonic_deadline
}

fn validate_initiator_sid(sid: &str) -> Result<(), EnrollmentAuthorityError> {
    if sid.is_empty() || sid.len() > MAX_WINDOWS_SID_LENGTH || !sid.is_ascii() {
        return Err(EnrollmentAuthorityError::InvalidInitiatorSid);
    }

    let components: Vec<&str> = sid.split('-').collect();

    if components.len() < 4 || components[0] != "S" || components[1] != "1" {
        return Err(EnrollmentAuthorityError::InvalidInitiatorSid);
    }

    if components[2..].iter().any(|component| {
        component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(EnrollmentAuthorityError::InvalidInitiatorSid);
    }

    Ok(())
}

fn random_session_id() -> SessionId {
    loop {
        let mut bytes = [0u8; 16];

        rand::rng().fill_bytes(&mut bytes);

        if bytes.iter().any(|value| *value != 0) {
            return SessionId(bytes);
        }
    }
}

fn random_nonce() -> Nonce {
    loop {
        let mut bytes = [0u8; 32];

        rand::rng().fill_bytes(&mut bytes);

        if bytes.iter().any(|value| *value != 0) {
            return Nonce(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use phonekey_protocol::enrollment::{
        create_enrollment_proof, decode_enrollment_challenge, derive_pairing_code,
        encode_enrollment_proof,
    };

    use p256::ecdsa::SigningKey;

    use tempfile::tempdir;

    const START_MS: u64 = 1_000_000;

    const SID_A: &str = "S-1-5-21-111111111-222222222-333333333-1001";

    const SID_B: &str = "S-1-5-21-111111111-222222222-333333333-1002";

    fn windows_device_id() -> DeviceId {
        DeviceId([0x11; 16])
    }

    fn android_device_id() -> DeviceId {
        DeviceId([0x22; 16])
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[0x01; 32]).unwrap()
    }

    fn monotonic_start() -> Instant {
        Instant::now()
    }

    fn authority() -> (tempfile::TempDir, EnrollmentAuthority) {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let authority = EnrollmentAuthority::from_trust_path(path);

        (directory, authority)
    }

    fn begin_standard(
        authority: &mut EnrollmentAuthority,
        monotonic: Instant,
    ) -> EnrollmentChallenge {
        let bytes = authority
            .begin(windows_device_id(), SID_A, START_MS, monotonic)
            .unwrap();

        decode_enrollment_challenge(&bytes).unwrap()
    }

    fn proof_for(challenge: &EnrollmentChallenge) -> EnrollmentProof {
        create_enrollment_proof(&signing_key(), android_device_id(), challenge).unwrap()
    }

    #[test]
    fn begin_creates_valid_fresh_challenge_and_binds_initiator() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        assert_eq!(challenge.windows_device_id, windows_device_id());

        assert_eq!(challenge.issued_at_ms, START_MS - CLOCK_SKEW_ALLOWANCE_MS);

        assert_eq!(challenge.expires_at_ms, START_MS + ENROLLMENT_TTL_MS);

        assert!(challenge.enrollment_id.0.iter().any(|value| *value != 0));

        assert!(challenge.nonce.0.iter().any(|value| *value != 0));

        assert!(authority.has_pending());
    }

    #[test]
    fn early_clock_saturates_without_extending_enrollment_expiry() {
        let (_directory, mut authority) = authority();
        let challenge = decode_enrollment_challenge(
            &authority
                .begin(windows_device_id(), SID_A, 1_000, monotonic_start())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(challenge.issued_at_ms, 0);
        assert_eq!(challenge.expires_at_ms, 1_000 + ENROLLMENT_TTL_MS);
    }

    #[test]
    fn invalid_initiator_sid_is_rejected() {
        let (_directory, mut authority) = authority();

        let result = authority.begin(
            windows_device_id(),
            "not-a-windows-sid",
            START_MS,
            monotonic_start(),
        );

        assert!(matches!(
            result,
            Err(EnrollmentAuthorityError::InvalidInitiatorSid)
        ));

        assert!(!authority.has_pending());
    }

    #[test]
    fn duplicate_begin_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        begin_standard(&mut authority, monotonic);

        let second = authority.begin(
            windows_device_id(),
            SID_B,
            START_MS + 1,
            monotonic + Duration::from_millis(1),
        );

        assert!(matches!(
            second,
            Err(EnrollmentAuthorityError::AlreadyPending)
        ));
    }

    #[test]
    fn valid_proof_produces_exact_pairing_code() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let expected_code = derive_pairing_code(&challenge, &proof).unwrap();

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let service_code = authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        assert_eq!(service_code, expected_code);
    }

    #[test]
    fn duplicate_proof_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        let duplicate = authority.submit_proof(
            &proof_bytes,
            START_MS + 1_001,
            monotonic + Duration::from_millis(1_001),
        );

        assert!(matches!(
            duplicate,
            Err(EnrollmentAuthorityError::ProofAlreadySubmitted)
        ));
    }

    #[test]
    fn wrong_enrollment_id_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let mut proof = proof_for(&challenge);

        proof.enrollment_id = SessionId([0x99; 16]);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        assert!(
            authority
                .submit_proof(
                    &proof_bytes,
                    START_MS + 1_000,
                    monotonic + Duration::from_millis(1_000),
                )
                .is_err()
        );

        assert!(
            trust_store::load_at(authority.trust_path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let mut proof = proof_for(&challenge);

        let other_key = SigningKey::from_slice(&[0x02; 32]).unwrap();

        let other_point = other_key.verifying_key().to_sec1_point(false);

        proof
            .public_key_sec1
            .copy_from_slice(other_point.as_bytes());

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        assert!(
            authority
                .submit_proof(
                    &proof_bytes,
                    START_MS + 1_000,
                    monotonic + Duration::from_millis(1_000),
                )
                .is_err()
        );

        assert!(
            trust_store::load_at(authority.trust_path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn replayed_proof_from_cancelled_transaction_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let first_challenge = begin_standard(&mut authority, monotonic);

        let old_proof = proof_for(&first_challenge);

        let old_proof_bytes = encode_enrollment_proof(&old_proof).unwrap();

        authority.cancel(SID_A).unwrap();

        authority
            .begin(
                windows_device_id(),
                SID_A,
                START_MS + 2_000,
                monotonic + Duration::from_millis(2_000),
            )
            .unwrap();

        assert!(
            authority
                .submit_proof(
                    &old_proof_bytes,
                    START_MS + 3_000,
                    monotonic + Duration::from_millis(3_000),
                )
                .is_err()
        );

        assert!(
            trust_store::load_at(authority.trust_path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pairing_code_requires_verified_proof() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        begin_standard(&mut authority, monotonic);

        let result = authority.pairing_code_for_initiator(
            SID_A,
            START_MS + 1_000,
            monotonic + Duration::from_millis(1_000),
        );

        assert!(matches!(
            result,
            Err(EnrollmentAuthorityError::PairingNotReady)
        ));

        assert!(authority.has_pending());
    }

    #[test]
    fn pairing_code_is_visible_only_to_initiating_administrator() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let expected_code = derive_pairing_code(&challenge, &proof).unwrap();

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        let wrong_admin = authority.pairing_code_for_initiator(
            SID_B,
            START_MS + 2_000,
            monotonic + Duration::from_millis(2_000),
        );

        assert!(matches!(
            wrong_admin,
            Err(EnrollmentAuthorityError::CallerMismatch)
        ));

        assert!(authority.has_pending());

        let code = authority
            .pairing_code_for_initiator(
                SID_A,
                START_MS + 2_001,
                monotonic + Duration::from_millis(2_001),
            )
            .unwrap();

        assert_eq!(code, expected_code);

        assert!(authority.has_pending());
    }

    #[test]
    fn pairing_code_exact_expiry_boundary_fails_closed() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        let result = authority.pairing_code_for_initiator(
            SID_A,
            START_MS + ENROLLMENT_TTL_MS,
            monotonic + Duration::from_millis(ENROLLMENT_TTL_MS - 1),
        );

        assert!(matches!(result, Err(EnrollmentAuthorityError::Expired)));

        assert!(!authority.has_pending());
    }

    #[test]
    fn confirm_before_proof_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        begin_standard(&mut authority, monotonic);

        let result = authority.confirm(
            123_456,
            SID_A,
            START_MS + 1_000,
            monotonic + Duration::from_millis(1_000),
        );

        assert!(matches!(
            result,
            Err(EnrollmentAuthorityError::PairingNotReady)
        ));

        assert!(authority.has_pending());
    }

    #[test]
    fn wrong_pairing_code_consumes_transaction() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let code = authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        let wrong_code = if code == 999_999 { 0 } else { code + 1 };

        let result = authority.confirm(
            wrong_code,
            SID_A,
            START_MS + 2_000,
            monotonic + Duration::from_millis(2_000),
        );

        assert!(matches!(
            result,
            Err(EnrollmentAuthorityError::PairingCodeMismatch)
        ));

        assert!(!authority.has_pending());

        assert!(
            trust_store::load_at(authority.trust_path())
                .unwrap()
                .is_none()
        );

        let retry = authority.confirm(
            code,
            SID_A,
            START_MS + 2_001,
            monotonic + Duration::from_millis(2_001),
        );

        assert!(matches!(
            retry,
            Err(EnrollmentAuthorityError::NoPendingEnrollment)
        ));
    }

    #[test]
    fn different_administrator_cannot_confirm_transaction() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let code = authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        let wrong_admin = authority.confirm(
            code,
            SID_B,
            START_MS + 2_000,
            monotonic + Duration::from_millis(2_000),
        );

        assert!(matches!(
            wrong_admin,
            Err(EnrollmentAuthorityError::CallerMismatch)
        ));

        assert!(authority.has_pending());

        authority
            .confirm(
                code,
                SID_A,
                START_MS + 2_001,
                monotonic + Duration::from_millis(2_001),
            )
            .unwrap();

        assert!(!authority.has_pending());
    }

    #[test]
    fn different_administrator_cannot_cancel_transaction() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        begin_standard(&mut authority, monotonic);

        let wrong_admin = authority.cancel(SID_B);

        assert!(matches!(
            wrong_admin,
            Err(EnrollmentAuthorityError::CallerMismatch)
        ));

        assert!(authority.has_pending());

        authority.cancel(SID_A).unwrap();

        assert!(!authority.has_pending());
    }

    #[test]
    fn confirmed_pairing_commits_privileged_trust() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let expected_public_key = proof.public_key_sec1;

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let code = authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        authority
            .confirm(
                code,
                SID_A,
                START_MS + 2_000,
                monotonic + Duration::from_millis(2_000),
            )
            .unwrap();

        assert!(!authority.has_pending());

        let trusted = trust_store::load_at(authority.trust_path())
            .unwrap()
            .unwrap();

        assert_eq!(trusted.android_device_id, android_device_id());

        assert_eq!(trusted.public_key_sec1, expected_public_key);
    }

    #[test]
    fn tampered_proof_is_rejected_without_trust() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let mut proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let last = proof_bytes.len() - 1;

        proof_bytes[last] ^= 0x01;

        assert!(
            authority
                .submit_proof(
                    &proof_bytes,
                    START_MS + 1_000,
                    monotonic + Duration::from_millis(1_000),
                )
                .is_err()
        );

        assert!(
            trust_store::load_at(authority.trust_path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn exact_wall_clock_expiry_boundary_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let result = authority.submit_proof(
            &proof_bytes,
            START_MS + ENROLLMENT_TTL_MS,
            monotonic + Duration::from_millis(ENROLLMENT_TTL_MS - 1),
        );

        assert!(matches!(result, Err(EnrollmentAuthorityError::Expired)));

        assert!(!authority.has_pending());
    }

    #[test]
    fn wall_clock_rollback_fails_closed() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let result = authority.submit_proof(
            &proof_bytes,
            START_MS - 1,
            monotonic + Duration::from_millis(1_000),
        );

        assert!(matches!(result, Err(EnrollmentAuthorityError::Expired)));

        assert!(!authority.has_pending());
    }

    #[test]
    fn monotonic_deadline_expires_even_if_wall_clock_remains_inside_window() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let result = authority.submit_proof(
            &proof_bytes,
            START_MS + 1_000,
            monotonic + Duration::from_millis(ENROLLMENT_TTL_MS),
        );

        assert!(matches!(result, Err(EnrollmentAuthorityError::Expired)));

        assert!(!authority.has_pending());
    }

    #[test]
    fn exact_pairing_expiry_boundary_is_rejected() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let code = authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        let result = authority.confirm(
            code,
            SID_A,
            START_MS + ENROLLMENT_TTL_MS,
            monotonic + Duration::from_millis(ENROLLMENT_TTL_MS - 1),
        );

        assert!(matches!(result, Err(EnrollmentAuthorityError::Expired)));

        assert!(!authority.has_pending());

        assert!(
            trust_store::load_at(authority.trust_path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn enrollment_is_blocked_once_phone_is_trusted() {
        let (_directory, mut authority) = authority();

        let monotonic = monotonic_start();

        let challenge = begin_standard(&mut authority, monotonic);

        let proof = proof_for(&challenge);

        let proof_bytes = encode_enrollment_proof(&proof).unwrap();

        let code = authority
            .submit_proof(
                &proof_bytes,
                START_MS + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap();

        authority
            .confirm(
                code,
                SID_A,
                START_MS + 2_000,
                monotonic + Duration::from_millis(2_000),
            )
            .unwrap();

        let result = authority.begin(
            windows_device_id(),
            SID_A,
            START_MS + 3_000,
            monotonic + Duration::from_millis(3_000),
        );

        assert!(matches!(
            result,
            Err(EnrollmentAuthorityError::AlreadyEnrolled)
        ));
    }

    #[test]
    fn cancel_destroys_pending_enrollment_for_same_initiator() {
        let (_directory, mut authority) = authority();

        begin_standard(&mut authority, monotonic_start());

        assert!(authority.has_pending());

        authority.cancel(SID_A).unwrap();

        assert!(!authority.has_pending());
    }

    #[test]
    fn cancel_without_pending_fails_closed() {
        let (_directory, mut authority) = authority();

        assert!(matches!(
            authority.cancel(SID_A),
            Err(EnrollmentAuthorityError::NoPendingEnrollment)
        ));
    }
}
