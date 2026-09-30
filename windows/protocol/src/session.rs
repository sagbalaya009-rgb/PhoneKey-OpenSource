use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::error::ProtocolError;
use crate::messages::{LoginChallenge, LoginOperation};
use crate::proof::{LoginProof, verify_login_proof};
use crate::types::{DeviceId, MAX_LOGIN_SESSION_TTL_MS, SessionId};

/*
 * A consumed session is no longer active, so an old proof cannot
 * authenticate after this marker is removed.
 *
 * The replay cache exists to:
 *
 * 1. explicitly classify recent replay attempts;
 * 2. prevent accidental immediate session-ID reuse;
 * 3. do so with a strict memory bound.
 *
 * Ten minutes is far longer than PhoneKey's login challenge TTL.
 */
const CONSUMED_REPLAY_RETENTION: Duration = Duration::from_secs(10 * 60);

const MAX_CONSUMED_SESSIONS: usize = 1_024;

#[derive(Debug, Default)]
pub struct SessionStore {
    active: HashMap<SessionId, LoginChallenge>,

    consumed: HashMap<SessionId, Instant>,

    consumed_order: VecDeque<(SessionId, Instant)>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, challenge: LoginChallenge) -> Result<(), ProtocolError> {
        self.register_at(challenge, Instant::now())
    }

    pub fn register_at(
        &mut self,
        challenge: LoginChallenge,
        monotonic_now: Instant,
    ) -> Result<(), ProtocolError> {
        self.prune_consumed(monotonic_now);

        challenge.validate()?;

        let lifetime = challenge
            .expires_at_ms
            .checked_sub(challenge.issued_at_ms)
            .ok_or(ProtocolError::SessionLifetimeTooLong)?;

        if lifetime > MAX_LOGIN_SESSION_TTL_MS {
            return Err(ProtocolError::SessionLifetimeTooLong);
        }

        let session_id = challenge.session_id;

        if self.active.contains_key(&session_id) || self.consumed.contains_key(&session_id) {
            return Err(ProtocolError::DuplicateSession);
        }

        self.active.insert(session_id, challenge);

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_consume(
        &mut self,
        session_id: SessionId,
        proof: &LoginProof,
        expected_android_device_id: &DeviceId,
        public_key_sec1: &[u8],
        expected_windows_device_id: &DeviceId,
        expected_account_binding: &[u8],
        expected_operation: LoginOperation,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.verify_and_consume_at(
            session_id,
            proof,
            expected_android_device_id,
            public_key_sec1,
            expected_windows_device_id,
            expected_account_binding,
            expected_operation,
            now_ms,
            Instant::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_consume_at(
        &mut self,
        session_id: SessionId,
        proof: &LoginProof,
        expected_android_device_id: &DeviceId,
        public_key_sec1: &[u8],
        expected_windows_device_id: &DeviceId,
        expected_account_binding: &[u8],
        expected_operation: LoginOperation,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<(), ProtocolError> {
        self.prune_consumed(monotonic_now);

        if self.consumed.contains_key(&session_id) {
            return Err(ProtocolError::SessionAlreadyConsumed);
        }

        let challenge = self
            .active
            .get(&session_id)
            .ok_or(ProtocolError::UnknownSession)?;

        if now_ms < challenge.issued_at_ms {
            return Err(ProtocolError::SessionNotYetValid);
        }

        if now_ms >= challenge.expires_at_ms {
            return Err(ProtocolError::SessionExpired);
        }

        if challenge.windows_device_id != *expected_windows_device_id {
            return Err(ProtocolError::SessionBindingMismatch);
        }

        if challenge.account_binding.as_slice() != expected_account_binding {
            return Err(ProtocolError::SessionBindingMismatch);
        }

        if challenge.operation != expected_operation {
            return Err(ProtocolError::SessionBindingMismatch);
        }

        verify_login_proof(
            proof,
            expected_android_device_id,
            public_key_sec1,
            challenge,
        )?;

        self.active.remove(&session_id);

        self.record_consumed(session_id, monotonic_now);

        Ok(())
    }

    pub fn discard(&mut self, session_id: &SessionId) -> bool {
        self.active.remove(session_id).is_some()
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn is_consumed(&mut self, session_id: &SessionId) -> bool {
        self.is_consumed_at(session_id, Instant::now())
    }

    pub fn is_consumed_at(&mut self, session_id: &SessionId, monotonic_now: Instant) -> bool {
        self.prune_consumed(monotonic_now);

        self.consumed.contains_key(session_id)
    }

    pub fn consumed_count(&mut self) -> usize {
        self.consumed_count_at(Instant::now())
    }

    pub fn consumed_count_at(&mut self, monotonic_now: Instant) -> usize {
        self.prune_consumed(monotonic_now);

        self.consumed.len()
    }

    fn record_consumed(&mut self, session_id: SessionId, monotonic_now: Instant) {
        self.consumed.insert(session_id, monotonic_now);

        self.consumed_order.push_back((session_id, monotonic_now));

        self.prune_consumed(monotonic_now);
    }

    fn prune_consumed(&mut self, monotonic_now: Instant) {
        while let Some((session_id, consumed_at)) = self.consumed_order.front().copied() {
            let age = monotonic_now.saturating_duration_since(consumed_at);

            if age < CONSUMED_REPLAY_RETENTION {
                break;
            }

            self.consumed_order.pop_front();

            if self
                .consumed
                .get(&session_id)
                .is_some_and(|stored| *stored == consumed_at)
            {
                self.consumed.remove(&session_id);
            }
        }

        while self.consumed.len() > MAX_CONSUMED_SESSIONS {
            let Some((session_id, consumed_at)) = self.consumed_order.pop_front() else {
                break;
            };

            if self
                .consumed
                .get(&session_id)
                .is_some_and(|stored| *stored == consumed_at)
            {
                self.consumed.remove(&session_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proof::create_login_proof;
    use crate::types::Nonce;

    use p256::ecdsa::SigningKey;

    fn session_id(value: u128) -> SessionId {
        SessionId(value.to_be_bytes())
    }

    fn challenge(session: SessionId) -> LoginChallenge {
        LoginChallenge {
            windows_device_id: DeviceId([0x11; 16]),

            session_id: session,

            nonce: Nonce([0x22; 32]),

            issued_at_ms: 1_000,

            expires_at_ms: 2_000,

            operation: LoginOperation::Logon,

            account_binding: b"S-1-5-21-1-2-3-1001".to_vec(),
        }
    }

    #[test]
    fn successful_session_moves_from_active_to_consumed() {
        let mut store = SessionStore::new();

        let monotonic = Instant::now();

        let key = SigningKey::from_slice(&[0x01; 32]).unwrap();

        let android_id = DeviceId([0x33; 16]);

        let session = session_id(1);

        let challenge = challenge(session);

        store.register_at(challenge.clone(), monotonic).unwrap();

        let proof = create_login_proof(&key, android_id, &challenge).unwrap();

        let encoded_point = key.verifying_key().to_sec1_point(false);

        store
            .verify_and_consume_at(
                session,
                &proof,
                &android_id,
                encoded_point.as_bytes(),
                &challenge.windows_device_id,
                &challenge.account_binding,
                LoginOperation::Logon,
                1_500,
                monotonic + Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(store.active_count(), 0);

        assert!(store.is_consumed_at(&session, monotonic + Duration::from_secs(1)));
    }

    #[test]
    fn recent_consumed_session_cannot_be_registered_again() {
        let mut store = SessionStore::new();

        let monotonic = Instant::now();

        let session = session_id(2);

        store.record_consumed(session, monotonic);

        assert!(matches!(
            store.register_at(challenge(session), monotonic + Duration::from_secs(1),),
            Err(ProtocolError::DuplicateSession)
        ));
    }

    #[test]
    fn consumed_entry_expires_at_retention_boundary() {
        let mut store = SessionStore::new();

        let monotonic = Instant::now();

        let session = session_id(3);

        store.record_consumed(session, monotonic);

        assert!(store.is_consumed_at(
            &session,
            monotonic + CONSUMED_REPLAY_RETENTION - Duration::from_millis(1)
        ));

        assert!(!store.is_consumed_at(&session, monotonic + CONSUMED_REPLAY_RETENTION));

        assert_eq!(
            store.consumed_count_at(monotonic + CONSUMED_REPLAY_RETENTION),
            0
        );
    }

    #[test]
    fn consumed_replay_cache_has_strict_upper_bound() {
        let mut store = SessionStore::new();

        let monotonic = Instant::now();

        for index in 1..=(MAX_CONSUMED_SESSIONS + 64) {
            store.record_consumed(
                session_id(index as u128),
                monotonic + Duration::from_millis(index as u64),
            );
        }

        assert_eq!(
            store.consumed_count_at(monotonic + Duration::from_secs(2)),
            MAX_CONSUMED_SESSIONS
        );

        assert!(!store.is_consumed_at(&session_id(1), monotonic + Duration::from_secs(2)));

        assert!(store.is_consumed_at(
            &session_id((MAX_CONSUMED_SESSIONS + 64) as u128),
            monotonic + Duration::from_secs(2)
        ));
    }
}
