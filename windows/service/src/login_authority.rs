use crate::account_binding::{self, AccountBindingError, AuthorizedAccount};
use crate::trust_store;

use phonekey_protocol::error::ProtocolError;
use phonekey_protocol::messages::{LoginChallenge, LoginOperation, encode_login_challenge};
use phonekey_protocol::proof::decode_login_proof;
use phonekey_protocol::session::SessionStore;
use phonekey_protocol::types::{DeviceId, MAX_LOGIN_SESSION_TTL_MS, Nonce, SessionId};

use rand::RngCore;

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use thiserror::Error;

// The Android client caps signed login sessions at 60 seconds. BLE discovery
// begins immediately; QR-triggered advertising or the updated app's early
// challenge rendezvous preserves the QR-to-challenge binding.
const LOGIN_TTL_MS: u64 = MAX_LOGIN_SESSION_TTL_MS;

#[derive(Debug)]
struct PendingLogin {
    challenge: LoginChallenge,
    created_at_ms: u64,
    initiator_sid: String,
    monotonic_deadline: Instant,
}

#[derive(Debug)]
pub struct BegunLogin {
    pub session_id: SessionId,
    pub challenge_bytes: Vec<u8>,
    pub expires_at_ms: u64,
    pub trusted_android_device_id: DeviceId,
    pub trusted_public_key_sec1: [u8; 65],
}

#[derive(Debug, Error)]
pub enum LoginAuthorityError {
    #[error("no privileged PhoneKey enrollment exists")]
    NoTrustedPhone,

    #[error("no permanently authorized Windows account exists")]
    NoAuthorizedAccount,

    #[error("this Windows account is not authorized for the enrolled phone")]
    UnauthorizedAccount,

    #[error("authorized Windows account is bound to a different Android identity")]
    AuthorizedPhoneMismatch,

    #[error("protected Windows account authorization failed: {0}")]
    AccountBinding(#[source] AccountBindingError),

    #[error("a login transaction is already pending")]
    AlreadyPending,

    #[error("no login transaction is pending")]
    NoPendingLogin,

    #[error("login transaction caller does not match its initiator")]
    CallerMismatch,

    #[error("login transaction expired")]
    Expired,

    #[error("login proof is a replay")]
    Replay,

    #[error("login clock overflow")]
    ClockOverflow,

    #[error("generated login challenge failed protocol validation: {0}")]
    ChallengeProtocol(#[source] ProtocolError),

    #[error("login proof rejected: {0}")]
    ProofRejected(#[source] ProtocolError),

    #[error("privileged PhoneKey trust failed: {0}")]
    Trust(#[source] io::Error),
}

pub struct LoginAuthority {
    windows_device_id: DeviceId,
    trust_path: PathBuf,
    account_binding_path: PathBuf,
    sessions: SessionStore,
    pending: Option<PendingLogin>,
}

impl LoginAuthority {
    pub fn password_vault_path(&self) -> PathBuf {
        self.trust_path.with_file_name("password_vault.bin")
    }

    pub fn local_password_vault_path(&self) -> PathBuf {
        self.trust_path.with_file_name("password_vault_local.bin")
    }

    pub fn bound_account_sid(&self) -> std::io::Result<Option<String>> {
        crate::account_binding::load_at(&self.account_binding_path)
            .map(|account| account.map(|value| value.windows_sid))
            .map_err(std::io::Error::other)
    }
    pub fn production(windows_device_id: DeviceId) -> io::Result<Self> {
        Ok(Self::from_paths(
            windows_device_id,
            trust_store::trusted_phone_path()?,
            account_binding::authorized_account_path()?,
        ))
    }

    pub fn from_trust_path(windows_device_id: DeviceId, trust_path: PathBuf) -> Self {
        let account_binding_path = trust_path.with_file_name("authorized_account.json");

        Self::from_paths(windows_device_id, trust_path, account_binding_path)
    }

    pub fn from_paths(
        windows_device_id: DeviceId,
        trust_path: PathBuf,
        account_binding_path: PathBuf,
    ) -> Self {
        Self {
            windows_device_id,
            trust_path,
            account_binding_path,
            sessions: SessionStore::new(),
            pending: None,
        }
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn begin(
        &mut self,
        caller_sid: &str,
        operation: LoginOperation,
        now_ms: u64,
    ) -> Result<BegunLogin, LoginAuthorityError> {
        self.begin_at(caller_sid, operation, now_ms, Instant::now())
    }

    fn begin_at(
        &mut self,
        caller_sid: &str,
        operation: LoginOperation,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<BegunLogin, LoginAuthorityError> {
        self.expire_pending_if_needed(now_ms, monotonic_now);

        if self.pending.is_some() {
            return Err(LoginAuthorityError::AlreadyPending);
        }

        validate_caller_sid(caller_sid)?;

        let trusted_phone =
            match trust_store::load_at(&self.trust_path).map_err(LoginAuthorityError::Trust)? {
                Some(phone) => phone,

                None => {
                    return Err(LoginAuthorityError::NoTrustedPhone);
                }
            };

        let authorized_account =
            self.authorized_account_for(caller_sid, &trusted_phone.android_device_id)?;

        let expires_at_ms = now_ms
            .checked_add(LOGIN_TTL_MS)
            .ok_or(LoginAuthorityError::ClockOverflow)?;

        let monotonic_deadline = monotonic_now
            .checked_add(Duration::from_millis(LOGIN_TTL_MS))
            .ok_or(LoginAuthorityError::ClockOverflow)?;

        let challenge = LoginChallenge {
            windows_device_id: self.windows_device_id,

            session_id: random_session_id(),

            nonce: random_nonce(),

            issued_at_ms: now_ms,

            expires_at_ms,

            operation,

            /*
             * Account authorization is derived only from
             * protected LocalSystem state and the SID Windows
             * returned for the authenticated named-pipe client.
             */
            account_binding: authorized_account.windows_sid.as_bytes().to_vec(),
        };

        challenge
            .validate()
            .map_err(LoginAuthorityError::ChallengeProtocol)?;

        let encoded =
            encode_login_challenge(&challenge).map_err(LoginAuthorityError::ChallengeProtocol)?;

        self.sessions
            .register_at(challenge.clone(), monotonic_now)
            .map_err(LoginAuthorityError::ChallengeProtocol)?;

        let session_id = challenge.session_id;

        self.pending = Some(PendingLogin {
            challenge,

            created_at_ms: now_ms,

            initiator_sid: caller_sid.to_owned(),

            monotonic_deadline,
        });

        Ok(BegunLogin {
            session_id,
            challenge_bytes: encoded,
            expires_at_ms,
            trusted_android_device_id: trusted_phone.android_device_id,
            trusted_public_key_sec1: trusted_phone.public_key_sec1,
        })
    }

    pub fn validate_trust_snapshot(
        &self,
        caller_sid: &str,
        android_device_id: DeviceId,
        public_key_sec1: &[u8; 65],
    ) -> Result<(), LoginAuthorityError> {
        let current = trust_store::load_at(&self.trust_path)
            .map_err(LoginAuthorityError::Trust)?
            .ok_or(LoginAuthorityError::NoTrustedPhone)?;
        if current.android_device_id != android_device_id
            || &current.public_key_sec1 != public_key_sec1
        {
            return Err(LoginAuthorityError::AuthorizedPhoneMismatch);
        }
        self.authorized_account_for(caller_sid, &current.android_device_id)?;
        Ok(())
    }

    pub fn submit_proof(
        &mut self,
        proof_bytes: &[u8],
        caller_sid: &str,
        now_ms: u64,
    ) -> Result<(), LoginAuthorityError> {
        self.submit_proof_at(proof_bytes, caller_sid, now_ms, Instant::now())
    }

    fn submit_proof_at(
        &mut self,
        proof_bytes: &[u8],
        caller_sid: &str,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<(), LoginAuthorityError> {
        /*
         * Decode before inspecting pending state so an already
         * consumed recent session can be classified explicitly
         * as a replay.
         */
        let proof = match decode_login_proof(proof_bytes) {
            Ok(proof) => proof,

            Err(error) => {
                let should_destroy = self
                    .pending
                    .as_ref()
                    .map(|pending| pending.initiator_sid == caller_sid)
                    .unwrap_or(false);

                if should_destroy && let Some(pending) = self.pending.take() {
                    self.sessions.discard(&pending.challenge.session_id);
                }

                return Err(LoginAuthorityError::ProofRejected(error));
            }
        };

        if self
            .sessions
            .is_consumed_at(&proof.session_id, monotonic_now)
        {
            return Err(LoginAuthorityError::Replay);
        }

        let pending = self
            .pending
            .as_ref()
            .ok_or(LoginAuthorityError::NoPendingLogin)?;

        if pending.initiator_sid != caller_sid {
            /*
             * Another Windows SID cannot consume or destroy the
             * legitimate initiator's pending authentication.
             */
            return Err(LoginAuthorityError::CallerMismatch);
        }

        if login_expired(pending, now_ms, monotonic_now) {
            let session_id = pending.challenge.session_id;

            self.sessions.discard(&session_id);

            self.pending = None;

            return Err(LoginAuthorityError::Expired);
        }

        let challenge = pending.challenge.clone();

        let session_id = challenge.session_id;

        let trusted_phone =
            match trust_store::load_at(&self.trust_path).map_err(LoginAuthorityError::Trust)? {
                Some(phone) => phone,

                None => {
                    self.sessions.discard(&session_id);

                    self.pending = None;

                    return Err(LoginAuthorityError::NoTrustedPhone);
                }
            };

        let authorized_account =
            match self.authorized_account_for(caller_sid, &trusted_phone.android_device_id) {
                Ok(account) => account,

                Err(error) => {
                    self.sessions.discard(&session_id);

                    self.pending = None;

                    return Err(error);
                }
            };

        let verification = self.sessions.verify_and_consume_at(
            session_id,
            &proof,
            &trusted_phone.android_device_id,
            &trusted_phone.public_key_sec1,
            &self.windows_device_id,
            authorized_account.windows_sid.as_bytes(),
            challenge.operation,
            now_ms,
            monotonic_now,
        );

        match verification {
            Ok(()) => {
                self.pending = None;

                Ok(())
            }

            Err(error) => {
                /*
                 * A same-user cryptographic failure destroys this
                 * challenge. Fresh randomness is required next.
                 */
                self.sessions.discard(&session_id);

                self.pending = None;

                Err(LoginAuthorityError::ProofRejected(error))
            }
        }
    }

    fn authorized_account_for(
        &self,
        caller_sid: &str,
        trusted_android_device_id: &DeviceId,
    ) -> Result<AuthorizedAccount, LoginAuthorityError> {
        let authorized = account_binding::load_at(&self.account_binding_path)
            .map_err(LoginAuthorityError::AccountBinding)?
            .ok_or(LoginAuthorityError::NoAuthorizedAccount)?;

        if authorized.android_device_id != *trusted_android_device_id {
            return Err(LoginAuthorityError::AuthorizedPhoneMismatch);
        }

        if authorized.windows_sid != caller_sid {
            return Err(LoginAuthorityError::UnauthorizedAccount);
        }

        Ok(authorized)
    }

    pub fn cancel(&mut self, caller_sid: &str) -> Result<(), LoginAuthorityError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(LoginAuthorityError::NoPendingLogin)?;

        if pending.initiator_sid != caller_sid {
            return Err(LoginAuthorityError::CallerMismatch);
        }

        let session_id = pending.challenge.session_id;

        self.sessions.discard(&session_id);

        self.pending = None;

        Ok(())
    }

    fn expire_pending_if_needed(&mut self, now_ms: u64, monotonic_now: Instant) {
        let should_expire = self
            .pending
            .as_ref()
            .map(|pending| login_expired(pending, now_ms, monotonic_now))
            .unwrap_or(false);

        if should_expire && let Some(pending) = self.pending.take() {
            self.sessions.discard(&pending.challenge.session_id);
        }
    }
}

fn login_expired(pending: &PendingLogin, now_ms: u64, monotonic_now: Instant) -> bool {
    now_ms < pending.created_at_ms
        || now_ms >= pending.challenge.expires_at_ms
        || monotonic_now >= pending.monotonic_deadline
}

fn validate_caller_sid(caller_sid: &str) -> Result<(), LoginAuthorityError> {
    if caller_sid.is_empty() || !caller_sid.is_ascii() || !caller_sid.starts_with("S-") {
        return Err(LoginAuthorityError::CallerMismatch);
    }

    Ok(())
}

fn random_session_id() -> SessionId {
    loop {
        let mut value = [0u8; 16];

        rand::rng().fill_bytes(&mut value);

        if value.iter().any(|byte| *byte != 0) {
            return SessionId(value);
        }
    }
}

fn random_nonce() -> Nonce {
    loop {
        let mut value = [0u8; 32];

        rand::rng().fill_bytes(&mut value);

        if value.iter().any(|byte| *byte != 0) {
            return Nonce(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::trust_store::{self, TrustedPhone};

    use p256::ecdsa::SigningKey;

    use phonekey_protocol::messages::{LoginOperation, decode_login_challenge};

    use phonekey_protocol::proof::{create_login_proof, encode_login_proof};

    use std::path::Path;

    use tempfile::tempdir;

    const WINDOWS_ID: DeviceId = DeviceId([0x44; 16]);

    const ANDROID_ID: DeviceId = DeviceId([0x55; 16]);

    const SID_A: &str = "S-1-5-21-111111111-222222222-333333333-1001";

    const SID_B: &str = "S-1-5-21-111111111-222222222-333333333-1002";

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[0x01; 32]).unwrap()
    }

    fn enroll_test_phone(path: &Path, key: &SigningKey) {
        let encoded_point = key.verifying_key().to_sec1_point(false);

        let mut public_key = [0u8; 65];

        public_key.copy_from_slice(encoded_point.as_bytes());

        trust_store::enroll_at(
            path,
            &TrustedPhone {
                android_device_id: ANDROID_ID,

                public_key_sec1: public_key,
            },
        )
        .unwrap();

        account_binding::bind_at(
            &path.with_file_name("authorized_account.json"),
            SID_A,
            ANDROID_ID,
        )
        .unwrap();
    }

    #[test]
    fn begin_requires_protected_trust() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        assert!(matches!(
            authority.begin(SID_A, LoginOperation::Logon, 1_000,),
            Err(LoginAuthorityError::NoTrustedPhone)
        ));
    }

    #[test]
    fn challenge_uses_real_service_and_sid_binding() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let bytes = authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        let challenge = decode_login_challenge(&bytes.challenge_bytes).unwrap();

        assert_eq!(challenge.windows_device_id, WINDOWS_ID);

        assert_eq!(challenge.operation, LoginOperation::Logon);

        assert_eq!(challenge.account_binding, SID_A.as_bytes());

        assert_eq!(challenge.issued_at_ms, 10_000);

        assert_eq!(challenge.expires_at_ms, 10_000 + LOGIN_TTL_MS);
    }

    #[test]
    fn duplicate_begin_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        authority
            .begin(SID_A, LoginOperation::Logon, 1_000)
            .unwrap();

        assert!(matches!(
            authority.begin(SID_A, LoginOperation::Logon, 2_000,),
            Err(LoginAuthorityError::AlreadyPending)
        ));
    }

    #[test]
    fn valid_proof_is_verified_and_consumed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let challenge_bytes = authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        let challenge = decode_login_challenge(&challenge_bytes.challenge_bytes).unwrap();

        let proof = create_login_proof(&key, ANDROID_ID, &challenge).unwrap();

        let proof_bytes = encode_login_proof(&proof).unwrap();

        authority.submit_proof(&proof_bytes, SID_A, 11_000).unwrap();

        assert!(!authority.has_pending());

        assert!(authority.sessions.is_consumed(&challenge.session_id));
    }

    #[test]
    fn successful_proof_replay_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let challenge_bytes = authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        let challenge = decode_login_challenge(&challenge_bytes.challenge_bytes).unwrap();

        let proof = create_login_proof(&key, ANDROID_ID, &challenge).unwrap();

        let proof_bytes = encode_login_proof(&proof).unwrap();

        authority.submit_proof(&proof_bytes, SID_A, 11_000).unwrap();

        assert!(matches!(
            authority.submit_proof(&proof_bytes, SID_A, 12_000,),
            Err(LoginAuthorityError::Replay)
        ));
    }

    #[test]
    fn wrong_windows_user_cannot_consume_login() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let challenge_bytes = authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        let challenge = decode_login_challenge(&challenge_bytes.challenge_bytes).unwrap();

        let proof = create_login_proof(&key, ANDROID_ID, &challenge).unwrap();

        let proof_bytes = encode_login_proof(&proof).unwrap();

        assert!(matches!(
            authority.submit_proof(&proof_bytes, SID_B, 11_000,),
            Err(LoginAuthorityError::CallerMismatch)
        ));

        assert!(authority.has_pending());
    }

    #[test]
    fn tampered_proof_fails_closed_and_destroys_challenge() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let challenge_bytes = authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        let challenge = decode_login_challenge(&challenge_bytes.challenge_bytes).unwrap();

        let mut proof = create_login_proof(&key, ANDROID_ID, &challenge).unwrap();

        proof.signature[0] ^= 0x01;

        let proof_bytes = encode_login_proof(&proof).unwrap();

        assert!(matches!(
            authority.submit_proof(&proof_bytes, SID_A, 11_000,),
            Err(LoginAuthorityError::ProofRejected(_))
        ));

        assert!(!authority.has_pending());

        assert_eq!(authority.sessions.active_count(), 0);
    }

    #[test]
    fn expired_login_is_destroyed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let challenge_bytes = authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        let challenge = decode_login_challenge(&challenge_bytes.challenge_bytes).unwrap();

        let proof = create_login_proof(&key, ANDROID_ID, &challenge).unwrap();

        let proof_bytes = encode_login_proof(&proof).unwrap();

        assert!(matches!(
            authority.submit_proof(&proof_bytes, SID_A, challenge.expires_at_ms,),
            Err(LoginAuthorityError::Expired)
        ));

        assert!(!authority.has_pending());
    }

    #[test]
    fn trusted_phone_without_authorized_account_cannot_begin() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        let encoded_point = key.verifying_key().to_sec1_point(false);

        let mut public_key = [0u8; 65];

        public_key.copy_from_slice(encoded_point.as_bytes());

        trust_store::enroll_at(
            &path,
            &TrustedPhone {
                android_device_id: ANDROID_ID,

                public_key_sec1: public_key,
            },
        )
        .unwrap();

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        assert!(matches!(
            authority.begin(SID_A, LoginOperation::Logon, 10_000,),
            Err(LoginAuthorityError::NoAuthorizedAccount)
        ));
    }

    #[test]
    fn unauthorized_windows_account_cannot_begin() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        assert!(matches!(
            authority.begin(SID_B, LoginOperation::Logon, 10_000,),
            Err(LoginAuthorityError::UnauthorizedAccount)
        ));

        assert!(!authority.has_pending());
    }

    #[test]
    fn authorized_account_bound_to_other_phone_fails_closed() {
        let directory = tempdir().unwrap();

        let trust_path = directory.path().join("trusted_phone.json");

        let account_path = directory.path().join("authorized_account.json");

        let key = signing_key();

        let encoded_point = key.verifying_key().to_sec1_point(false);

        let mut public_key = [0u8; 65];

        public_key.copy_from_slice(encoded_point.as_bytes());

        trust_store::enroll_at(
            &trust_path,
            &TrustedPhone {
                android_device_id: ANDROID_ID,

                public_key_sec1: public_key,
            },
        )
        .unwrap();

        account_binding::bind_at(&account_path, SID_A, DeviceId([0x77; 16])).unwrap();

        let mut authority = LoginAuthority::from_paths(WINDOWS_ID, trust_path, account_path);

        assert!(matches!(
            authority.begin(SID_A, LoginOperation::Logon, 10_000,),
            Err(LoginAuthorityError::AuthorizedPhoneMismatch)
        ));
    }

    #[test]
    fn malformed_proof_destroys_same_user_pending_challenge() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        assert!(matches!(
            authority.submit_proof(&[0xA0], SID_A, 11_000,),
            Err(LoginAuthorityError::ProofRejected(_))
        ));

        assert!(!authority.has_pending());

        assert_eq!(authority.sessions.active_count(), 0);
    }

    #[test]
    fn malformed_proof_from_other_sid_does_not_destroy_legitimate_pending_login() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        authority
            .begin(SID_A, LoginOperation::Logon, 10_000)
            .unwrap();

        assert!(matches!(
            authority.submit_proof(&[0xA0], SID_B, 11_000,),
            Err(LoginAuthorityError::ProofRejected(_))
        ));

        assert!(authority.has_pending());
    }

    #[test]
    fn different_sid_cannot_cancel_login() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        authority
            .begin(SID_A, LoginOperation::Unlock, 10_000)
            .unwrap();

        assert!(matches!(
            authority.cancel(SID_B),
            Err(LoginAuthorityError::CallerMismatch)
        ));

        assert!(authority.has_pending());

        authority.cancel(SID_A).unwrap();

        assert!(!authority.has_pending());
    }

    #[test]
    fn monotonic_deadline_expires_login_even_when_wall_clock_is_inside_window() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let monotonic = Instant::now();

        let challenge_bytes = authority
            .begin_at(SID_A, LoginOperation::Logon, 10_000, monotonic)
            .unwrap();

        let challenge = decode_login_challenge(&challenge_bytes.challenge_bytes).unwrap();

        let proof = create_login_proof(&key, ANDROID_ID, &challenge).unwrap();

        let proof_bytes = encode_login_proof(&proof).unwrap();

        let result = authority.submit_proof_at(
            &proof_bytes,
            SID_A,
            11_000,
            monotonic + Duration::from_millis(LOGIN_TTL_MS),
        );

        assert!(matches!(result, Err(LoginAuthorityError::Expired)));

        assert!(!authority.has_pending());

        assert_eq!(authority.sessions.active_count(), 0);
    }

    #[test]
    fn wall_clock_rollback_still_fails_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let monotonic = Instant::now();

        let challenge_bytes = authority
            .begin_at(SID_A, LoginOperation::Logon, 10_000, monotonic)
            .unwrap();

        let challenge = decode_login_challenge(&challenge_bytes.challenge_bytes).unwrap();

        let proof = create_login_proof(&key, ANDROID_ID, &challenge).unwrap();

        let proof_bytes = encode_login_proof(&proof).unwrap();

        let result = authority.submit_proof_at(
            &proof_bytes,
            SID_A,
            9_999,
            monotonic + Duration::from_secs(1),
        );

        assert!(matches!(result, Err(LoginAuthorityError::Expired)));

        assert!(!authority.has_pending());
    }

    #[test]
    fn monotonic_expiry_removes_stale_pending_before_fresh_begin() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let key = signing_key();

        enroll_test_phone(&path, &key);

        let mut authority = LoginAuthority::from_trust_path(WINDOWS_ID, path);

        let monotonic = Instant::now();

        let first = authority
            .begin_at(SID_A, LoginOperation::Logon, 10_000, monotonic)
            .unwrap();

        let first = decode_login_challenge(&first.challenge_bytes).unwrap();

        let second = authority
            .begin_at(
                SID_A,
                LoginOperation::Logon,
                10_001,
                monotonic + Duration::from_millis(LOGIN_TTL_MS),
            )
            .unwrap();

        let second = decode_login_challenge(&second.challenge_bytes).unwrap();

        assert_ne!(first.session_id, second.session_id);

        assert!(authority.has_pending());

        assert_eq!(authority.sessions.active_count(), 1);
    }
}
