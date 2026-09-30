use phonekey_protocol::types::{DeviceId, SessionId};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialLoginState {
    Pending,
    Scanning,
    Connecting,
    WaitingForProof,
    Verifying,
    Authenticated,
    Rejected,
    Expired,
    Cancelled,
    TransportError,
}

impl CredentialLoginState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Authenticated
                | Self::Rejected
                | Self::Expired
                | Self::Cancelled
                | Self::TransportError
        )
    }
}

#[derive(Debug, Clone)]
pub struct CredentialLoginTransaction {
    pub session_id: SessionId,
    pub target_sid: String,
    pub trusted_android_device_id: DeviceId,
    pub trusted_public_key_sec1: [u8; 65],
    pub state: CredentialLoginState,
    expires_at_ms: u64,
    monotonic_deadline: Instant,
    redeemed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRedeemError {
    Unavailable,
    Expired,
}

impl CredentialLoginTransaction {
    pub fn new(
        session_id: SessionId,
        target_sid: String,
        expires_at_ms: u64,
        monotonic_deadline: Instant,
        trusted_android_device_id: DeviceId,
        trusted_public_key_sec1: [u8; 65],
    ) -> Self {
        Self {
            session_id,
            target_sid,
            trusted_android_device_id,
            trusted_public_key_sec1,
            state: CredentialLoginState::Pending,
            expires_at_ms,
            monotonic_deadline,
            redeemed: false,
        }
    }

    pub fn redeem(
        &mut self,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<&str, CredentialRedeemError> {
        if self.state != CredentialLoginState::Authenticated || self.redeemed {
            return Err(CredentialRedeemError::Unavailable);
        }
        if now_ms >= self.expires_at_ms || monotonic_now >= self.monotonic_deadline {
            return Err(CredentialRedeemError::Expired);
        }
        self.redeemed = true;
        Ok(&self.target_sid)
    }

    pub fn transition(&mut self, next: CredentialLoginState) -> Result<(), &'static str> {
        if self.state.is_terminal() {
            return Err("terminal credential login transaction cannot transition");
        }

        self.state = next;

        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), &'static str> {
        self.transition(CredentialLoginState::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionId {
        SessionId([0x11; 16])
    }

    fn transaction() -> CredentialLoginTransaction {
        CredentialLoginTransaction::new(
            session(),
            "S-1-5-21-test".into(),
            60_000,
            Instant::now() + std::time::Duration::from_secs(60),
            DeviceId([1; 16]),
            [2; 65],
        )
    }

    #[test]
    fn terminal_state_cannot_be_resurrected() {
        let mut transaction = transaction();

        transaction
            .transition(CredentialLoginState::Authenticated)
            .unwrap();

        assert!(
            transaction
                .transition(CredentialLoginState::Scanning)
                .is_err()
        );
    }

    #[test]
    fn cancellation_is_terminal() {
        let mut transaction = transaction();

        transaction.cancel().unwrap();

        assert_eq!(transaction.state, CredentialLoginState::Cancelled);

        assert!(
            transaction
                .transition(CredentialLoginState::Authenticated)
                .is_err()
        );
    }

    #[test]
    fn authenticated_transaction_redeems_only_once_before_both_deadlines() {
        let mut valid = transaction();
        let now = Instant::now();
        assert!(valid.redeem(1, now).is_err());
        valid
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        assert_eq!(valid.redeem(1, now).unwrap(), "S-1-5-21-test");
        assert!(valid.redeem(1, now).is_err());

        let mut wall_expired = transaction();
        wall_expired
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        assert!(wall_expired.redeem(60_000, now).is_err());

        let mut monotonic_expired = transaction();
        monotonic_expired
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        assert!(
            monotonic_expired
                .redeem(1, now + std::time::Duration::from_secs(61))
                .is_err()
        );
    }
}
