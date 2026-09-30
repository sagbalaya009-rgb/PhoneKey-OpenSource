use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("non-canonical CBOR encoding")]
    NonCanonicalEncoding,

    #[error("malformed CBOR")]
    Malformed,

    #[error("message exceeds maximum size")]
    OversizedMessage,

    #[error("nesting exceeds maximum depth")]
    NestingTooDeep,

    #[error("unsupported CBOR type")]
    UnsupportedType,

    #[error("invalid map key")]
    InvalidMapKey,

    #[error("missing required field {0}")]
    MissingField(u16),

    #[error("unexpected field {0}")]
    UnexpectedField(u16),

    #[error("invalid type for field {0}")]
    InvalidFieldType(u16),

    #[error("invalid length for field {0}")]
    InvalidFieldLength(u16),

    #[error("invalid value for field {0}")]
    InvalidFieldValue(u16),

    #[error("invalid cryptographic key")]
    InvalidCryptoKey,

    #[error("invalid cryptographic signature")]
    InvalidSignature,

    #[error("proof does not match challenge")]
    ProofBindingMismatch,

    #[error("session does not exist")]
    UnknownSession,

    #[error("session has already been consumed")]
    SessionAlreadyConsumed,

    #[error("session is expired")]
    SessionExpired,

    #[error("session is not valid yet")]
    SessionNotYetValid,

    #[error("session lifetime exceeds maximum")]
    SessionLifetimeTooLong,

    #[error("session context does not match expected context")]
    SessionBindingMismatch,

    #[error("session already exists")]
    DuplicateSession,
}
