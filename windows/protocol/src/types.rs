pub const MAX_MESSAGE_SIZE: usize = 2048;
pub const MAX_NESTING_DEPTH: usize = 8;

pub const DEVICE_ID_LEN: usize = 16;
pub const SESSION_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 32;

pub const MAX_ACCOUNT_BINDING_LEN: usize = 256;

pub const MAX_LOGIN_SESSION_TTL_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; DEVICE_ID_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; SESSION_ID_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; NONCE_LEN]);
