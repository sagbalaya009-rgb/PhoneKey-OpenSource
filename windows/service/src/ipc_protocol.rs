use phonekey_protocol::messages::LoginOperation;
use phonekey_protocol::types::{DeviceId, SessionId};

use thiserror::Error;

pub const IPC_VERSION: u8 = 2;

pub const REQUEST_MAGIC: [u8; 4] = *b"PKI2";

pub const RESPONSE_MAGIC: [u8; 4] = *b"PKR2";

pub const HEADER_LENGTH: usize = 12;

pub const MAX_IPC_PAYLOAD: usize = 2_048;

pub const MAX_SID_TEXT_LENGTH: usize = 184;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    GetMachineContext = 1,
    BeginEnrollment = 2,
    SubmitEnrollmentProof = 3,
    ConfirmEnrollment = 4,
    CancelEnrollment = 5,
    BeginLogin = 6,
    SubmitLoginProof = 7,
    CancelLogin = 8,
    BindAuthorizedAccount = 9,
    GetEnrollmentPairingCode = 10,

    // Credential Provider commands are intentionally separate from
    // the normal signed-in-user broker login path.
    BeginCredentialProviderLogin = 11,
    SubmitCredentialProviderProof = 12,
    CancelCredentialProviderLogin = 13,
    GetCredentialProviderLoginStatus = 14,
    RedeemCredentialProviderLogin = 15,
    ProvisionPasswordVault = 16,
    RedeemCredentialProviderPassword = 17,
    RotatePasswordVault = 18,
    ProvisionLocalPasswordVault = 19,
    RedeemCredentialProviderLocalPassword = 20,
    RotateLocalPasswordVault = 21,
}

impl Command {
    pub fn from_byte(value: u8) -> Result<Self, IpcProtocolError> {
        match value {
            1 => Ok(Self::GetMachineContext),

            2 => Ok(Self::BeginEnrollment),

            3 => Ok(Self::SubmitEnrollmentProof),

            4 => Ok(Self::ConfirmEnrollment),

            5 => Ok(Self::CancelEnrollment),

            6 => Ok(Self::BeginLogin),

            7 => Ok(Self::SubmitLoginProof),

            8 => Ok(Self::CancelLogin),

            9 => Ok(Self::BindAuthorizedAccount),

            10 => Ok(Self::GetEnrollmentPairingCode),

            11 => Ok(Self::BeginCredentialProviderLogin),

            12 => Ok(Self::SubmitCredentialProviderProof),

            13 => Ok(Self::CancelCredentialProviderLogin),

            14 => Ok(Self::GetCredentialProviderLoginStatus),

            15 => Ok(Self::RedeemCredentialProviderLogin),
            16 => Ok(Self::ProvisionPasswordVault),
            17 => Ok(Self::RedeemCredentialProviderPassword),
            18 => Ok(Self::RotatePasswordVault),
            19 => Ok(Self::ProvisionLocalPasswordVault),
            20 => Ok(Self::RedeemCredentialProviderLocalPassword),
            21 => Ok(Self::RotateLocalPasswordVault),

            _ => Err(IpcProtocolError::UnknownCommand),
        }
    }

    pub fn requires_administrator(self) -> bool {
        match self {
            Self::GetMachineContext => false,

            Self::SubmitEnrollmentProof => false,

            Self::BeginLogin | Self::SubmitLoginProof | Self::CancelLogin => false,

            Self::BeginCredentialProviderLogin
            | Self::SubmitCredentialProviderProof
            | Self::CancelCredentialProviderLogin
            | Self::GetCredentialProviderLoginStatus => false,
            Self::RedeemCredentialProviderLogin => false,
            Self::ProvisionPasswordVault => true,
            Self::ProvisionLocalPasswordVault => true,
            Self::RedeemCredentialProviderPassword => false,
            Self::RedeemCredentialProviderLocalPassword => false,
            Self::RotatePasswordVault => true,
            Self::RotateLocalPasswordVault => true,

            Self::BeginEnrollment
            | Self::ConfirmEnrollment
            | Self::CancelEnrollment
            | Self::BindAuthorizedAccount
            | Self::GetEnrollmentPairingCode => true,
        }
    }

    pub fn requires_system(self) -> bool {
        matches!(
            self,
            Self::BeginCredentialProviderLogin
                | Self::SubmitCredentialProviderProof
                | Self::CancelCredentialProviderLogin
                | Self::GetCredentialProviderLoginStatus
                | Self::RedeemCredentialProviderLogin
                | Self::RedeemCredentialProviderPassword
                | Self::RedeemCredentialProviderLocalPassword
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Success = 0,

    BadRequest = 1,

    Unauthorized = 2,

    Conflict = 3,

    Expired = 4,

    CryptographicRejection = 5,

    InternalError = 255,
}

impl ResponseStatus {
    pub fn from_byte(value: u8) -> Result<Self, IpcProtocolError> {
        match value {
            0 => Ok(Self::Success),

            1 => Ok(Self::BadRequest),

            2 => Ok(Self::Unauthorized),

            3 => Ok(Self::Conflict),

            4 => Ok(Self::Expired),

            5 => Ok(Self::CryptographicRejection),

            255 => Ok(Self::InternalError),

            _ => Err(IpcProtocolError::UnknownStatus),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub command: Command,

    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: ResponseStatus,

    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpcProtocolError {
    #[error("IPC frame is shorter than its header")]
    TruncatedHeader,

    #[error("invalid IPC message magic")]
    InvalidMagic,

    #[error("unsupported IPC protocol version")]
    UnsupportedVersion,

    #[error("IPC reserved bytes must be zero")]
    NonZeroReserved,

    #[error("unknown IPC command")]
    UnknownCommand,

    #[error("unknown IPC response status")]
    UnknownStatus,

    #[error("IPC payload exceeds maximum size")]
    PayloadTooLarge,

    #[error("IPC payload length does not match frame length")]
    PayloadLengthMismatch,

    #[error("IPC command requires an empty payload")]
    ExpectedEmptyPayload,

    #[error("IPC command requires a payload")]
    ExpectedPayload,

    #[error("pairing confirmation payload is invalid")]
    InvalidPairingCodePayload,

    #[error("pairing code is outside its valid range")]
    PairingCodeOutOfRange,

    #[error("login operation payload is invalid")]
    InvalidLoginOperationPayload,

    #[error("login operation value is unknown")]
    UnknownLoginOperation,

    #[error("machine-context SID is invalid")]
    InvalidSid,

    #[error("machine-context payload is malformed")]
    InvalidMachineContext,

    #[error("credential-provider IPC payload is malformed")]
    InvalidCredentialProviderPayload,
}

pub fn encode_request(command: Command, payload: &[u8]) -> Result<Vec<u8>, IpcProtocolError> {
    validate_request_payload(command, payload)?;

    encode_frame(&REQUEST_MAGIC, command as u8, payload)
}

pub fn decode_request(bytes: &[u8]) -> Result<Request, IpcProtocolError> {
    let (discriminator, payload) = decode_frame(bytes, &REQUEST_MAGIC)?;

    let command = Command::from_byte(discriminator)?;

    validate_request_payload(command, &payload)?;

    Ok(Request { command, payload })
}

pub fn encode_response(
    status: ResponseStatus,
    payload: &[u8],
) -> Result<Vec<u8>, IpcProtocolError> {
    encode_frame(&RESPONSE_MAGIC, status as u8, payload)
}

pub fn decode_response(bytes: &[u8]) -> Result<Response, IpcProtocolError> {
    let (discriminator, payload) = decode_frame(bytes, &RESPONSE_MAGIC)?;

    let status = ResponseStatus::from_byte(discriminator)?;

    Ok(Response { status, payload })
}

pub fn encode_pairing_code_payload(pairing_code: u32) -> Result<[u8; 4], IpcProtocolError> {
    if pairing_code >= 1_000_000 {
        return Err(IpcProtocolError::PairingCodeOutOfRange);
    }

    Ok(pairing_code.to_be_bytes())
}

pub fn decode_pairing_code_payload(payload: &[u8]) -> Result<u32, IpcProtocolError> {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| IpcProtocolError::InvalidPairingCodePayload)?;

    let pairing_code = u32::from_be_bytes(bytes);

    if pairing_code >= 1_000_000 {
        return Err(IpcProtocolError::PairingCodeOutOfRange);
    }

    Ok(pairing_code)
}

pub fn encode_login_operation_payload(operation: LoginOperation) -> [u8; 1] {
    match operation {
        LoginOperation::Logon => [1],
        LoginOperation::Unlock => [2],
    }
}

pub fn decode_login_operation_payload(payload: &[u8]) -> Result<LoginOperation, IpcProtocolError> {
    let bytes: [u8; 1] = payload
        .try_into()
        .map_err(|_| IpcProtocolError::InvalidLoginOperationPayload)?;

    match bytes[0] {
        1 => Ok(LoginOperation::Logon),
        2 => Ok(LoginOperation::Unlock),
        _ => Err(IpcProtocolError::UnknownLoginOperation),
    }
}

pub fn encode_credential_provider_begin_payload(
    operation: LoginOperation,
    target_sid: &str,
) -> Result<Vec<u8>, IpcProtocolError> {
    validate_sid(target_sid)?;

    let sid_bytes = target_sid.as_bytes();
    let sid_length = u16::try_from(sid_bytes.len()).map_err(|_| IpcProtocolError::InvalidSid)?;

    let operation = encode_login_operation_payload(operation);

    let mut payload = Vec::with_capacity(1 + 2 + sid_bytes.len());

    payload.extend_from_slice(&operation);
    payload.extend_from_slice(&sid_length.to_be_bytes());
    payload.extend_from_slice(sid_bytes);

    Ok(payload)
}

pub fn decode_credential_provider_begin_payload(
    payload: &[u8],
) -> Result<(LoginOperation, String), IpcProtocolError> {
    if payload.len() < 4 {
        return Err(IpcProtocolError::InvalidCredentialProviderPayload);
    }

    let operation = decode_login_operation_payload(&payload[0..1])?;

    let sid = decode_credential_provider_sid_payload(&payload[1..])?;

    Ok((operation, sid))
}

pub fn encode_credential_provider_sid_payload(
    target_sid: &str,
) -> Result<Vec<u8>, IpcProtocolError> {
    validate_sid(target_sid)?;

    let sid_bytes = target_sid.as_bytes();
    let sid_length = u16::try_from(sid_bytes.len()).map_err(|_| IpcProtocolError::InvalidSid)?;

    let mut payload = Vec::with_capacity(2 + sid_bytes.len());

    payload.extend_from_slice(&sid_length.to_be_bytes());
    payload.extend_from_slice(sid_bytes);

    Ok(payload)
}

pub fn decode_credential_provider_sid_payload(payload: &[u8]) -> Result<String, IpcProtocolError> {
    let (sid, consumed) = decode_credential_provider_sid_prefix(payload)?;

    if consumed != payload.len() {
        return Err(IpcProtocolError::InvalidCredentialProviderPayload);
    }

    Ok(sid)
}

pub fn encode_credential_provider_proof_payload(
    target_sid: &str,
    proof: &[u8],
) -> Result<Vec<u8>, IpcProtocolError> {
    if proof.is_empty() {
        return Err(IpcProtocolError::ExpectedPayload);
    }

    let mut payload = encode_credential_provider_sid_payload(target_sid)?;

    payload.extend_from_slice(proof);

    if payload.len() > MAX_IPC_PAYLOAD {
        return Err(IpcProtocolError::PayloadTooLarge);
    }

    Ok(payload)
}

pub fn decode_credential_provider_proof_payload(
    payload: &[u8],
) -> Result<(String, Vec<u8>), IpcProtocolError> {
    let (sid, consumed) = decode_credential_provider_sid_prefix(payload)?;

    if consumed >= payload.len() {
        return Err(IpcProtocolError::ExpectedPayload);
    }

    Ok((sid, payload[consumed..].to_vec()))
}

fn decode_credential_provider_sid_prefix(
    payload: &[u8],
) -> Result<(String, usize), IpcProtocolError> {
    if payload.len() < 3 {
        return Err(IpcProtocolError::InvalidCredentialProviderPayload);
    }

    let sid_length = u16::from_be_bytes([payload[0], payload[1]]) as usize;

    if sid_length == 0 || sid_length > MAX_SID_TEXT_LENGTH {
        return Err(IpcProtocolError::InvalidSid);
    }

    let end = 2usize
        .checked_add(sid_length)
        .ok_or(IpcProtocolError::InvalidCredentialProviderPayload)?;

    if end > payload.len() {
        return Err(IpcProtocolError::InvalidCredentialProviderPayload);
    }

    let sid = std::str::from_utf8(&payload[2..end])
        .map_err(|_| IpcProtocolError::InvalidSid)?
        .to_owned();

    validate_sid(&sid)?;

    Ok((sid, end))
}

pub fn encode_credential_provider_transaction_payload(session_id: &SessionId) -> [u8; 16] {
    session_id.0
}

pub fn decode_credential_provider_transaction_payload(
    payload: &[u8],
) -> Result<SessionId, IpcProtocolError> {
    let bytes: [u8; 16] = payload
        .try_into()
        .map_err(|_| IpcProtocolError::InvalidCredentialProviderPayload)?;

    if bytes.iter().all(|byte| *byte == 0) {
        return Err(IpcProtocolError::InvalidCredentialProviderPayload);
    }

    Ok(SessionId(bytes))
}
pub fn encode_machine_context_payload(
    windows_device_id: &DeviceId,
    caller_sid: &str,
) -> Result<Vec<u8>, IpcProtocolError> {
    validate_sid(caller_sid)?;

    let sid_bytes = caller_sid.as_bytes();

    let sid_length = u16::try_from(sid_bytes.len()).map_err(|_| IpcProtocolError::InvalidSid)?;

    let mut payload = Vec::with_capacity(16 + 2 + sid_bytes.len());

    payload.extend_from_slice(&windows_device_id.0);

    payload.extend_from_slice(&sid_length.to_be_bytes());

    payload.extend_from_slice(sid_bytes);

    Ok(payload)
}

pub fn decode_machine_context_payload(
    payload: &[u8],
) -> Result<(DeviceId, String), IpcProtocolError> {
    const FIXED_LENGTH: usize = 18;

    if payload.len() < FIXED_LENGTH {
        return Err(IpcProtocolError::InvalidMachineContext);
    }

    let mut device_id = [0u8; 16];

    device_id.copy_from_slice(&payload[0..16]);

    if device_id.iter().all(|value| *value == 0) {
        return Err(IpcProtocolError::InvalidMachineContext);
    }

    let sid_length = u16::from_be_bytes([payload[16], payload[17]]) as usize;

    if sid_length == 0 || sid_length > MAX_SID_TEXT_LENGTH {
        return Err(IpcProtocolError::InvalidMachineContext);
    }

    let expected_length = FIXED_LENGTH
        .checked_add(sid_length)
        .ok_or(IpcProtocolError::InvalidMachineContext)?;

    if payload.len() != expected_length {
        return Err(IpcProtocolError::InvalidMachineContext);
    }

    let sid = std::str::from_utf8(&payload[FIXED_LENGTH..])
        .map_err(|_| IpcProtocolError::InvalidSid)?
        .to_owned();

    validate_sid(&sid)?;

    Ok((DeviceId(device_id), sid))
}

fn validate_request_payload(command: Command, payload: &[u8]) -> Result<(), IpcProtocolError> {
    match command {
        Command::GetMachineContext
        | Command::BeginEnrollment
        | Command::CancelEnrollment
        | Command::CancelLogin
        | Command::BindAuthorizedAccount
        | Command::GetEnrollmentPairingCode => {
            if !payload.is_empty() {
                return Err(IpcProtocolError::ExpectedEmptyPayload);
            }
        }

        Command::SubmitEnrollmentProof | Command::SubmitLoginProof => {
            if payload.is_empty() {
                return Err(IpcProtocolError::ExpectedPayload);
            }
        }

        Command::ConfirmEnrollment => {
            decode_pairing_code_payload(payload)?;
        }

        Command::BeginLogin => {
            decode_login_operation_payload(payload)?;
        }

        Command::BeginCredentialProviderLogin => {
            decode_credential_provider_begin_payload(payload)?;
        }

        Command::SubmitCredentialProviderProof => {
            decode_credential_provider_proof_payload(payload)?;
        }

        Command::CancelCredentialProviderLogin => {
            decode_credential_provider_transaction_payload(payload)?;
        }

        Command::GetCredentialProviderLoginStatus | Command::RedeemCredentialProviderLogin => {
            decode_credential_provider_transaction_payload(payload)?;
        }
        Command::RedeemCredentialProviderPassword
        | Command::RedeemCredentialProviderLocalPassword => {
            decode_credential_provider_transaction_payload(payload)?;
        }
        Command::ProvisionPasswordVault
        | Command::RotatePasswordVault
        | Command::ProvisionLocalPasswordVault
        | Command::RotateLocalPasswordVault => {
            if payload.len() < 2 || payload.len() > 1024 || payload.len() % 2 != 0 {
                return Err(IpcProtocolError::ExpectedPayload);
            }
        }
    }

    Ok(())
}

fn validate_sid(sid: &str) -> Result<(), IpcProtocolError> {
    if sid.is_empty() || sid.len() > MAX_SID_TEXT_LENGTH {
        return Err(IpcProtocolError::InvalidSid);
    }

    if !sid.is_ascii() {
        return Err(IpcProtocolError::InvalidSid);
    }

    if !sid.starts_with("S-") {
        return Err(IpcProtocolError::InvalidSid);
    }

    Ok(())
}

fn encode_frame(
    magic: &[u8; 4],
    discriminator: u8,
    payload: &[u8],
) -> Result<Vec<u8>, IpcProtocolError> {
    if payload.len() > MAX_IPC_PAYLOAD {
        return Err(IpcProtocolError::PayloadTooLarge);
    }

    let payload_length =
        u32::try_from(payload.len()).map_err(|_| IpcProtocolError::PayloadTooLarge)?;

    let mut frame = Vec::with_capacity(HEADER_LENGTH + payload.len());

    frame.extend_from_slice(magic);

    frame.push(IPC_VERSION);

    frame.push(discriminator);

    frame.extend_from_slice(&[0, 0]);

    frame.extend_from_slice(&payload_length.to_be_bytes());

    frame.extend_from_slice(payload);

    Ok(frame)
}

fn decode_frame(bytes: &[u8], expected_magic: &[u8; 4]) -> Result<(u8, Vec<u8>), IpcProtocolError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(IpcProtocolError::TruncatedHeader);
    }

    if &bytes[0..4] != expected_magic {
        return Err(IpcProtocolError::InvalidMagic);
    }

    if bytes[4] != IPC_VERSION {
        return Err(IpcProtocolError::UnsupportedVersion);
    }

    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(IpcProtocolError::NonZeroReserved);
    }

    let payload_length = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;

    if payload_length > MAX_IPC_PAYLOAD {
        return Err(IpcProtocolError::PayloadTooLarge);
    }

    let expected_length = HEADER_LENGTH
        .checked_add(payload_length)
        .ok_or(IpcProtocolError::PayloadTooLarge)?;

    if bytes.len() != expected_length {
        return Err(IpcProtocolError::PayloadLengthMismatch);
    }

    Ok((bytes[5], bytes[HEADER_LENGTH..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_sid() -> &'static str {
        "S-1-5-21-123456789-987654321-111111111-1001"
    }

    #[test]
    fn every_command_round_trips() {
        let cases = [
            (Command::GetMachineContext, Vec::new()),
            (Command::BeginEnrollment, Vec::new()),
            (Command::SubmitEnrollmentProof, vec![1, 2, 3]),
            (
                Command::ConfirmEnrollment,
                123_456u32.to_be_bytes().to_vec(),
            ),
            (Command::CancelEnrollment, Vec::new()),
            (Command::BindAuthorizedAccount, Vec::new()),
            (Command::GetEnrollmentPairingCode, Vec::new()),
        ];

        for (command, payload) in cases {
            let encoded = encode_request(command, &payload).unwrap();

            let decoded = decode_request(&encoded).unwrap();

            assert_eq!(decoded.command, command);

            assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn response_round_trips() {
        let encoded = encode_response(ResponseStatus::Success, &[1, 2, 3, 4]).unwrap();

        let decoded = decode_response(&encoded).unwrap();

        assert_eq!(decoded.status, ResponseStatus::Success);

        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(
            decode_request(&[0u8; 11]),
            Err(IpcProtocolError::TruncatedHeader)
        );
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut frame = encode_request(Command::GetMachineContext, &[]).unwrap();

        frame[0] = b'X';

        assert_eq!(decode_request(&frame), Err(IpcProtocolError::InvalidMagic));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut frame = encode_request(Command::GetMachineContext, &[]).unwrap();

        frame[4] = 99;

        assert_eq!(
            decode_request(&frame),
            Err(IpcProtocolError::UnsupportedVersion)
        );
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        let mut frame = encode_request(Command::GetMachineContext, &[]).unwrap();

        frame[6] = 1;

        assert_eq!(
            decode_request(&frame),
            Err(IpcProtocolError::NonZeroReserved)
        );
    }

    #[test]
    fn unknown_command_is_rejected() {
        let frame = encode_frame(&REQUEST_MAGIC, 200, &[]).unwrap();

        assert_eq!(
            decode_request(&frame),
            Err(IpcProtocolError::UnknownCommand)
        );
    }

    #[test]
    fn unknown_response_status_is_rejected() {
        let frame = encode_frame(&RESPONSE_MAGIC, 200, &[]).unwrap();

        assert_eq!(
            decode_response(&frame),
            Err(IpcProtocolError::UnknownStatus)
        );
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let payload = vec![0u8; MAX_IPC_PAYLOAD + 1];

        assert_eq!(
            encode_request(Command::SubmitEnrollmentProof, &payload,),
            Err(IpcProtocolError::PayloadTooLarge)
        );
    }

    #[test]
    fn incorrect_payload_length_is_rejected() {
        let mut frame = encode_request(Command::SubmitEnrollmentProof, &[1, 2, 3]).unwrap();

        frame[11] = 4;

        assert_eq!(
            decode_request(&frame),
            Err(IpcProtocolError::PayloadLengthMismatch)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut frame = encode_request(Command::GetMachineContext, &[]).unwrap();

        frame.push(0);

        assert_eq!(
            decode_request(&frame),
            Err(IpcProtocolError::PayloadLengthMismatch)
        );
    }

    #[test]
    fn begin_enrollment_requires_empty_payload() {
        assert_eq!(
            encode_request(Command::BeginEnrollment, &[1],),
            Err(IpcProtocolError::ExpectedEmptyPayload)
        );
    }

    #[test]
    fn proof_submission_requires_payload() {
        assert_eq!(
            encode_request(Command::SubmitEnrollmentProof, &[],),
            Err(IpcProtocolError::ExpectedPayload)
        );
    }

    #[test]
    fn valid_pairing_code_round_trips() {
        let encoded = encode_pairing_code_payload(411_429).unwrap();

        let decoded = decode_pairing_code_payload(&encoded).unwrap();

        assert_eq!(decoded, 411_429);
    }

    #[test]
    fn pairing_code_must_be_four_bytes() {
        assert_eq!(
            decode_pairing_code_payload(&[1, 2, 3]),
            Err(IpcProtocolError::InvalidPairingCodePayload)
        );
    }

    #[test]
    fn pairing_code_must_be_below_one_million() {
        assert_eq!(
            encode_pairing_code_payload(1_000_000),
            Err(IpcProtocolError::PairingCodeOutOfRange)
        );
    }

    #[test]
    fn machine_context_round_trips() {
        let device_id = DeviceId([0x55; 16]);

        let payload = encode_machine_context_payload(&device_id, example_sid()).unwrap();

        let (decoded_device_id, decoded_sid) = decode_machine_context_payload(&payload).unwrap();

        assert_eq!(decoded_device_id, device_id);

        assert_eq!(decoded_sid, example_sid());
    }

    #[test]
    fn all_zero_machine_id_is_rejected() {
        let payload = encode_machine_context_payload(&DeviceId([0x55; 16]), example_sid()).unwrap();

        let mut corrupted = payload;

        corrupted[0..16].fill(0);

        assert_eq!(
            decode_machine_context_payload(&corrupted),
            Err(IpcProtocolError::InvalidMachineContext)
        );
    }

    #[test]
    fn invalid_sid_is_rejected() {
        assert_eq!(
            encode_machine_context_payload(&DeviceId([0x55; 16]), "not-a-windows-sid",),
            Err(IpcProtocolError::InvalidSid)
        );
    }

    #[test]
    fn trust_changing_enrollment_commands_require_administrator() {
        assert!(Command::BeginEnrollment.requires_administrator());

        assert!(!Command::SubmitEnrollmentProof.requires_administrator());

        assert!(Command::ConfirmEnrollment.requires_administrator());

        assert!(Command::CancelEnrollment.requires_administrator());
        assert!(Command::BindAuthorizedAccount.requires_administrator());
        assert!(Command::GetEnrollmentPairingCode.requires_administrator());
    }

    #[test]
    fn login_commands_round_trip_and_are_unprivileged() {
        let begin = encode_request(
            Command::BeginLogin,
            &encode_login_operation_payload(LoginOperation::Logon),
        )
        .unwrap();

        let decoded_begin = decode_request(&begin).unwrap();

        assert_eq!(decoded_begin.command, Command::BeginLogin);
        assert_eq!(decoded_begin.payload, vec![1]);

        let proof = encode_request(Command::SubmitLoginProof, &[1, 2, 3]).unwrap();

        assert_eq!(
            decode_request(&proof).unwrap().command,
            Command::SubmitLoginProof
        );

        let cancel = encode_request(Command::CancelLogin, &[]).unwrap();

        assert_eq!(
            decode_request(&cancel).unwrap().command,
            Command::CancelLogin
        );

        assert!(!Command::BeginLogin.requires_administrator());
        assert!(!Command::SubmitLoginProof.requires_administrator());
        assert!(!Command::CancelLogin.requires_administrator());
    }

    #[test]
    fn invalid_login_operation_is_rejected() {
        assert_eq!(
            encode_request(Command::BeginLogin, &[99]),
            Err(IpcProtocolError::UnknownLoginOperation)
        );

        assert_eq!(
            encode_request(Command::BeginLogin, &[]),
            Err(IpcProtocolError::InvalidLoginOperationPayload)
        );
    }

    #[test]
    fn machine_context_does_not_require_administrator() {
        assert!(!Command::GetMachineContext.requires_administrator());
    }

    #[test]
    fn credential_provider_commands_are_system_only() {
        let commands = [
            Command::BeginCredentialProviderLogin,
            Command::SubmitCredentialProviderProof,
            Command::CancelCredentialProviderLogin,
            Command::GetCredentialProviderLoginStatus,
        ];

        for command in commands {
            assert!(command.requires_system());
            assert!(!command.requires_administrator());
        }

        assert!(!Command::BeginLogin.requires_system());
        assert!(!Command::SubmitLoginProof.requires_system());
        assert!(!Command::CancelLogin.requires_system());
    }

    #[test]
    fn credential_provider_begin_payload_round_trips() {
        let sid = example_sid();

        let payload = encode_credential_provider_begin_payload(LoginOperation::Logon, sid).unwrap();

        let (operation, decoded_sid) = decode_credential_provider_begin_payload(&payload).unwrap();

        assert_eq!(operation, LoginOperation::Logon);
        assert_eq!(decoded_sid, sid);
    }

    #[test]
    fn credential_provider_unlock_payload_round_trips() {
        let sid = example_sid();

        let payload =
            encode_credential_provider_begin_payload(LoginOperation::Unlock, sid).unwrap();

        let (operation, decoded_sid) = decode_credential_provider_begin_payload(&payload).unwrap();

        assert_eq!(operation, LoginOperation::Unlock);
        assert_eq!(decoded_sid, sid);
    }

    #[test]
    fn credential_provider_proof_payload_round_trips() {
        let sid = example_sid();
        let proof = [0xAA, 0xBB, 0xCC, 0xDD];

        let payload = encode_credential_provider_proof_payload(sid, &proof).unwrap();

        let (decoded_sid, decoded_proof) =
            decode_credential_provider_proof_payload(&payload).unwrap();

        assert_eq!(decoded_sid, sid);
        assert_eq!(decoded_proof, proof);
    }

    #[test]
    fn credential_provider_transaction_payload_round_trips() {
        let session = SessionId([0xA5; 16]);

        let payload = encode_credential_provider_transaction_payload(&session);

        assert_eq!(
            decode_credential_provider_transaction_payload(&payload,).unwrap(),
            session,
        );
    }

    #[test]
    fn credential_provider_transaction_payload_is_strict() {
        assert_eq!(
            decode_credential_provider_transaction_payload(&[0x11; 15],),
            Err(IpcProtocolError::InvalidCredentialProviderPayload,),
        );

        assert_eq!(
            decode_credential_provider_transaction_payload(&[0x11; 17],),
            Err(IpcProtocolError::InvalidCredentialProviderPayload,),
        );

        assert_eq!(
            decode_credential_provider_transaction_payload(&[0x00; 16],),
            Err(IpcProtocolError::InvalidCredentialProviderPayload,),
        );
    }

    #[test]
    fn credential_provider_cancel_and_status_require_transaction_id() {
        let session = SessionId([0x5A; 16]);

        let transaction = encode_credential_provider_transaction_payload(&session);

        assert!(encode_request(Command::CancelCredentialProviderLogin, &transaction,).is_ok());

        assert!(encode_request(Command::GetCredentialProviderLoginStatus, &transaction,).is_ok());

        let legacy_sid = encode_credential_provider_sid_payload(example_sid()).unwrap();

        assert_eq!(
            encode_request(Command::CancelCredentialProviderLogin, &legacy_sid,),
            Err(IpcProtocolError::InvalidCredentialProviderPayload,),
        );

        assert_eq!(
            encode_request(Command::GetCredentialProviderLoginStatus, &legacy_sid,),
            Err(IpcProtocolError::InvalidCredentialProviderPayload,),
        );
    }

    #[test]
    fn credential_provider_cancel_sid_round_trips() {
        let sid = example_sid();

        let payload = encode_credential_provider_sid_payload(sid).unwrap();

        let decoded = decode_credential_provider_sid_payload(&payload).unwrap();

        assert_eq!(decoded, sid);
    }

    #[test]
    fn credential_provider_empty_proof_is_rejected() {
        assert_eq!(
            encode_credential_provider_proof_payload(example_sid(), &[]),
            Err(IpcProtocolError::ExpectedPayload)
        );
    }

    #[test]
    fn credential_provider_invalid_sid_is_rejected() {
        assert_eq!(
            encode_credential_provider_begin_payload(LoginOperation::Logon, "not-a-windows-sid",),
            Err(IpcProtocolError::InvalidSid)
        );
    }

    #[test]
    fn credential_provider_command_ids_are_frozen() {
        assert_eq!(Command::BeginCredentialProviderLogin as u8, 11);
        assert_eq!(Command::SubmitCredentialProviderProof as u8, 12);
        assert_eq!(Command::CancelCredentialProviderLogin as u8, 13);
        assert_eq!(Command::GetCredentialProviderLoginStatus as u8, 14);
        assert_eq!(Command::RedeemCredentialProviderLogin as u8, 15);
        assert_eq!(Command::ProvisionPasswordVault as u8, 16);
        assert_eq!(Command::RedeemCredentialProviderPassword as u8, 17);
        assert_eq!(Command::RotatePasswordVault as u8, 18);
        assert_eq!(Command::ProvisionLocalPasswordVault as u8, 19);
        assert_eq!(Command::RedeemCredentialProviderLocalPassword as u8, 20);
        assert_eq!(Command::RotateLocalPasswordVault as u8, 21);

        assert_eq!(
            Command::from_byte(11).unwrap(),
            Command::BeginCredentialProviderLogin
        );
        assert_eq!(
            Command::from_byte(12).unwrap(),
            Command::SubmitCredentialProviderProof
        );
        assert_eq!(
            Command::from_byte(13).unwrap(),
            Command::CancelCredentialProviderLogin
        );

        assert_eq!(
            Command::from_byte(14).unwrap(),
            Command::GetCredentialProviderLoginStatus
        );
        assert_eq!(
            Command::from_byte(15).unwrap(),
            Command::RedeemCredentialProviderLogin
        );
        assert_eq!(
            Command::from_byte(16).unwrap(),
            Command::ProvisionPasswordVault
        );
        assert_eq!(
            Command::from_byte(17).unwrap(),
            Command::RedeemCredentialProviderPassword
        );
        assert_eq!(
            Command::from_byte(18).unwrap(),
            Command::RotatePasswordVault
        );
        assert_eq!(
            Command::from_byte(19).unwrap(),
            Command::ProvisionLocalPasswordVault
        );
        assert_eq!(
            Command::from_byte(20).unwrap(),
            Command::RedeemCredentialProviderLocalPassword
        );
        assert_eq!(
            Command::from_byte(21).unwrap(),
            Command::RotateLocalPasswordVault
        );
    }

    #[test]
    fn local_password_commands_keep_the_same_authorization_and_shape_as_microsoft_passwords() {
        let transaction = [0x55; 16];
        assert!(Command::ProvisionLocalPasswordVault.requires_administrator());
        assert!(Command::RotateLocalPasswordVault.requires_administrator());
        assert!(Command::RedeemCredentialProviderLocalPassword.requires_system());
        assert!(encode_request(Command::ProvisionLocalPasswordVault, &[65, 0]).is_ok());
        assert!(encode_request(Command::RotateLocalPasswordVault, &[66, 0]).is_ok());
        assert!(
            encode_request(Command::RedeemCredentialProviderLocalPassword, &transaction).is_ok()
        );
        assert!(
            encode_request(Command::RedeemCredentialProviderLocalPassword, &[0x55; 15]).is_err()
        );
    }
}
