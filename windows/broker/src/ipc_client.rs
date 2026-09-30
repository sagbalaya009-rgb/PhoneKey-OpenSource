use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

// Read/write rights without FILE_CREATE_PIPE_INSTANCE (0x4), matching the ACL.
const PIPE_CLIENT_ACCESS: u32 = 0x0012_019b;
// Identification + effective-only. OpenOptionsExt adds SECURITY_SQOS_PRESENT.
const PIPE_CLIENT_QOS: u32 = 0x0009_0000;

const PIPE_PATH: &str = r"\\.\pipe\PhoneKey.Control.v2";

const REQUEST_MAGIC: [u8; 4] = *b"PKI2";

const RESPONSE_MAGIC: [u8; 4] = *b"PKR2";

const IPC_VERSION: u8 = 2;

const HEADER_LENGTH: usize = 12;

const MAX_PAYLOAD: usize = 2_048;

const COMMAND_BEGIN_ENROLLMENT: u8 = 2;

const COMMAND_SUBMIT_ENROLLMENT_PROOF: u8 = 3;

const COMMAND_CONFIRM_ENROLLMENT: u8 = 4;

const COMMAND_CANCEL_ENROLLMENT: u8 = 5;

const COMMAND_BEGIN_LOGIN: u8 = 6;

const COMMAND_SUBMIT_LOGIN_PROOF: u8 = 7;

const COMMAND_CANCEL_LOGIN: u8 = 8;

const COMMAND_BIND_AUTHORIZED_ACCOUNT: u8 = 9;

const COMMAND_GET_ENROLLMENT_PAIRING_CODE: u8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Success,
    BadRequest,
    Unauthorized,
    Conflict,
    Expired,
    CryptographicRejection,
    InternalError,
}

impl ResponseStatus {
    fn from_byte(value: u8) -> Result<Self, IpcClientError> {
        match value {
            0 => Ok(Self::Success),

            1 => Ok(Self::BadRequest),

            2 => Ok(Self::Unauthorized),

            3 => Ok(Self::Conflict),

            4 => Ok(Self::Expired),

            5 => Ok(Self::CryptographicRejection),

            255 => Ok(Self::InternalError),

            other => Err(IpcClientError::UnknownStatus(other)),
        }
    }
}

impl std::fmt::Display for ResponseStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(formatter, "Success"),

            Self::BadRequest => write!(formatter, "BadRequest"),

            Self::Unauthorized => write!(formatter, "Unauthorized"),

            Self::Conflict => write!(formatter, "Conflict"),

            Self::Expired => write!(formatter, "Expired"),

            Self::CryptographicRejection => write!(formatter, "CryptographicRejection"),

            Self::InternalError => write!(formatter, "InternalError"),
        }
    }
}

#[derive(Debug, Error)]
pub enum IpcClientError {
    #[error("PhoneKey service named pipe could not be opened: {0}")]
    PipeOpen(#[source] std::io::Error),

    #[error("PhoneKey IPC I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("PhoneKey IPC payload exceeds 2048 bytes")]
    PayloadTooLarge,

    #[error("PhoneKey IPC write was incomplete")]
    ShortWrite,

    #[error("PhoneKey IPC response has invalid magic")]
    InvalidMagic,

    #[error("PhoneKey IPC response uses an unsupported version")]
    UnsupportedVersion,

    #[error("PhoneKey IPC response reserved bytes are non-zero")]
    NonZeroReserved,

    #[error("PhoneKey IPC response payload exceeds maximum size")]
    ResponseTooLarge,

    #[error("PhoneKey IPC response unexpectedly contained a payload")]
    UnexpectedPayload,

    #[error("PhoneKey IPC response status {0} is unknown")]
    UnknownStatus(u8),

    #[error("PhoneKey service rejected the operation: {0}")]
    ServiceRejected(ResponseStatus),

    #[error("PhoneKey service returned malformed pairing-code data")]
    InvalidPairingCode,

    #[error("pairing code is outside its valid range")]
    PairingCodeOutOfRange,

    #[error("login operation must be 1 (Logon) or 2 (Unlock)")]
    InvalidLoginOperation,
}

struct Response {
    status: ResponseStatus,

    payload: Vec<u8>,
}

pub fn enrollment_challenge_path() -> PathBuf {
    std::env::temp_dir().join("PhoneKey.ServiceEnrollmentChallenge.v1.bin")
}

pub fn begin_enrollment() -> Result<Vec<u8>, IpcClientError> {
    let response = request(COMMAND_BEGIN_ENROLLMENT, &[])?;

    require_success(response)
}

pub fn submit_enrollment_proof(proof: &[u8]) -> Result<(), IpcClientError> {
    let response = request(COMMAND_SUBMIT_ENROLLMENT_PROOF, proof)?;

    /*
     * Normal broker receives only Success or Failure.
     *
     * Any success payload is a service-side confidentiality
     * regression and therefore fails closed here.
     */
    require_success_empty(response)
}

pub fn get_enrollment_pairing_code() -> Result<u32, IpcClientError> {
    let response = request(COMMAND_GET_ENROLLMENT_PAIRING_CODE, &[])?;

    let payload = require_success(response)?;

    decode_pairing_code(&payload)
}

pub fn confirm_enrollment(pairing_code: u32) -> Result<(), IpcClientError> {
    if pairing_code >= 1_000_000 {
        return Err(IpcClientError::PairingCodeOutOfRange);
    }

    let payload = pairing_code.to_be_bytes();

    let response = request(COMMAND_CONFIRM_ENROLLMENT, &payload)?;

    require_success(response)?;

    Ok(())
}

pub fn cancel_enrollment() -> Result<(), IpcClientError> {
    let response = request(COMMAND_CANCEL_ENROLLMENT, &[])?;

    require_success(response)?;

    Ok(())
}

pub fn begin_login(operation: u8) -> Result<Vec<u8>, IpcClientError> {
    if !matches!(operation, 1 | 2) {
        return Err(IpcClientError::InvalidLoginOperation);
    }

    let response = request(COMMAND_BEGIN_LOGIN, &[operation])?;

    require_success(response)
}

pub fn submit_login_proof(proof: &[u8]) -> Result<(), IpcClientError> {
    let response = request(COMMAND_SUBMIT_LOGIN_PROOF, proof)?;

    require_success(response)?;

    Ok(())
}

pub fn cancel_login() -> Result<(), IpcClientError> {
    let response = request(COMMAND_CANCEL_LOGIN, &[])?;

    require_success(response)?;

    Ok(())
}

pub fn bind_authorized_account() -> Result<(), IpcClientError> {
    let response = request(COMMAND_BIND_AUTHORIZED_ACCOUNT, &[])?;

    require_success(response)?;

    Ok(())
}
fn request(command: u8, payload: &[u8]) -> Result<Response, IpcClientError> {
    let frame = encode_request(command, payload)?;

    let mut pipe = connect_pipe()?;
    verify_server(&pipe)?;

    /*
     * One write = one message.
     *
     * The LocalSystem server intentionally requires
     * one complete IPC V2 request per named-pipe
     * message, so do not use write_all here.
     */
    let written = pipe.write(&frame)?;

    if written != frame.len() {
        return Err(IpcClientError::ShortWrite);
    }

    pipe.flush()?;

    decode_response_from(&mut pipe)
}

fn connect_pipe() -> Result<File, IpcClientError> {
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        match OpenOptions::new()
            .access_mode(PIPE_CLIENT_ACCESS)
            .security_qos_flags(PIPE_CLIENT_QOS)
            .open(PIPE_PATH)
        {
            Ok(pipe) => return Ok(pipe),

            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(IpcClientError::PipeOpen(error));
                }

                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn encode_request(command: u8, payload: &[u8]) -> Result<Vec<u8>, IpcClientError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(IpcClientError::PayloadTooLarge);
    }

    let payload_length =
        u32::try_from(payload.len()).map_err(|_| IpcClientError::PayloadTooLarge)?;

    let mut frame = Vec::with_capacity(HEADER_LENGTH + payload.len());

    frame.extend_from_slice(&REQUEST_MAGIC);

    frame.push(IPC_VERSION);

    frame.push(command);

    frame.extend_from_slice(&[0, 0]);

    frame.extend_from_slice(&payload_length.to_be_bytes());

    frame.extend_from_slice(payload);

    Ok(frame)
}

fn decode_response_from(pipe: &mut File) -> Result<Response, IpcClientError> {
    let mut header = [0u8; HEADER_LENGTH];

    pipe.read_exact(&mut header)?;

    if header[0..4] != RESPONSE_MAGIC {
        return Err(IpcClientError::InvalidMagic);
    }

    if header[4] != IPC_VERSION {
        return Err(IpcClientError::UnsupportedVersion);
    }

    if header[6] != 0 || header[7] != 0 {
        return Err(IpcClientError::NonZeroReserved);
    }

    let status = ResponseStatus::from_byte(header[5])?;

    let payload_length =
        u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;

    if payload_length > MAX_PAYLOAD {
        return Err(IpcClientError::ResponseTooLarge);
    }

    let mut payload = vec![0u8; payload_length];

    pipe.read_exact(&mut payload)?;

    Ok(Response { status, payload })
}

fn require_success(response: Response) -> Result<Vec<u8>, IpcClientError> {
    if response.status != ResponseStatus::Success {
        return Err(IpcClientError::ServiceRejected(response.status));
    }

    Ok(response.payload)
}

fn require_success_empty(response: Response) -> Result<(), IpcClientError> {
    let payload = require_success(response)?;

    if !payload.is_empty() {
        return Err(IpcClientError::UnexpectedPayload);
    }

    Ok(())
}

fn decode_pairing_code(payload: &[u8]) -> Result<u32, IpcClientError> {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| IpcClientError::InvalidPairingCode)?;

    let code = u32::from_be_bytes(bytes);

    if code >= 1_000_000 {
        return Err(IpcClientError::PairingCodeOutOfRange);
    }

    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_frame_is_canonical() {
        let frame = encode_request(COMMAND_SUBMIT_ENROLLMENT_PROOF, &[1, 2, 3]).unwrap();

        assert_eq!(&frame[0..4], b"PKI2");

        assert_eq!(frame[4], 2);

        assert_eq!(frame[5], 3);

        assert_eq!(&frame[6..8], &[0, 0]);

        assert_eq!(&frame[8..12], &[0, 0, 0, 3]);

        assert_eq!(&frame[12..], &[1, 2, 3]);
    }

    #[test]
    fn oversized_request_is_rejected() {
        let payload = vec![0u8; MAX_PAYLOAD + 1];

        assert!(matches!(
            encode_request(COMMAND_SUBMIT_ENROLLMENT_PROOF, &payload,),
            Err(IpcClientError::PayloadTooLarge)
        ));
    }

    #[test]
    fn login_request_frames_are_canonical() {
        let begin = encode_request(COMMAND_BEGIN_LOGIN, &[1]).unwrap();

        assert_eq!(begin[5], COMMAND_BEGIN_LOGIN);

        assert_eq!(&begin[12..], &[1]);

        let proof = encode_request(COMMAND_SUBMIT_LOGIN_PROOF, &[1, 2, 3]).unwrap();

        assert_eq!(proof[5], COMMAND_SUBMIT_LOGIN_PROOF);

        let cancel = encode_request(COMMAND_CANCEL_LOGIN, &[]).unwrap();

        assert_eq!(cancel[5], COMMAND_CANCEL_LOGIN);
    }

    #[test]
    fn privileged_pairing_code_request_is_command_ten() {
        let frame = encode_request(COMMAND_GET_ENROLLMENT_PAIRING_CODE, &[]).unwrap();

        assert_eq!(frame[5], COMMAND_GET_ENROLLMENT_PAIRING_CODE);

        assert_eq!(&frame[12..], &[]);
    }

    #[test]
    fn proof_courier_rejects_unexpected_success_payload() {
        let response = Response {
            status: ResponseStatus::Success,

            payload: vec![0, 1, 2, 3],
        };

        assert!(matches!(
            require_success_empty(response),
            Err(IpcClientError::UnexpectedPayload)
        ));
    }

    #[test]
    fn pairing_code_decodes_big_endian() {
        assert_eq!(
            decode_pairing_code(&411_429u32.to_be_bytes()).unwrap(),
            411_429
        );
    }

    #[test]
    fn pairing_code_requires_four_bytes() {
        assert!(matches!(
            decode_pairing_code(&[1, 2, 3]),
            Err(IpcClientError::InvalidPairingCode)
        ));
    }

    #[test]
    fn pairing_code_must_be_below_one_million() {
        assert!(matches!(
            decode_pairing_code(&1_000_000u32.to_be_bytes()),
            Err(IpcClientError::PairingCodeOutOfRange)
        ));
    }
}

// Return whether a pipe owner is one of the identities PhoneKey explicitly
// trusts for the local control pipe. Keep this separate from verify_server so
// the security rule can be tested deterministically on any Windows runner.
fn is_privileged_pipe_owner(owner: windows::Win32::Security::PSID) -> bool {
    use windows::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

    unsafe {
        !owner.is_invalid()
            && (IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool())
    }
}

// Bind the connected pipe to a privileged owner before sending data. The
// LocalSystem service creates this pipe with Administrators as its owner on
// the pilot laptop. Ordinary users cannot query a SYSTEM process token, but
// can read the pipe owner through the READ_CONTROL right granted by its DACL.
fn verify_server(pipe: &File) -> Result<(), IpcClientError> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    let win = |error| IpcClientError::Io(std::io::Error::other(error));
    unsafe {
        let pipe_handle = HANDLE(pipe.as_raw_handle());
        let mut pid = 0;
        GetNamedPipeServerProcessId(pipe_handle, &mut pid).map_err(win)?;
        if pid == 0 {
            return Err(std::io::Error::other("pipe server PID is zero").into());
        }
        let mut owner = PSID::default();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let result = GetSecurityInfo(
            pipe_handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        );
        if result.0 != 0 {
            return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
        }
        let is_privileged = is_privileged_pipe_owner(owner);
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        if !is_privileged {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "PhoneKey pipe is not owned by a privileged identity",
            )
            .into());
        }
        let mut current_pid = 0;
        GetNamedPipeServerProcessId(pipe_handle, &mut current_pid).map_err(win)?;
        if current_pid != pid {
            return Err(std::io::Error::other("pipe server changed during authentication").into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod server_identity_tests {
    use super::*;

    #[test]
    fn rejects_unprivileged_well_known_owner() {
        use windows::Win32::Security::{
            CreateWellKnownSid, PSID, SECURITY_MAX_SID_SIZE, WinBuiltinUsersSid,
        };

        let mut sid_bytes = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_size = sid_bytes.len() as u32;
        unsafe {
            CreateWellKnownSid(
                WinBuiltinUsersSid,
                None,
                Some(PSID(sid_bytes.as_mut_ptr().cast())),
                &mut sid_size,
            )
            .unwrap();
        }

        assert!(!is_privileged_pipe_owner(PSID(
            sid_bytes.as_mut_ptr().cast()
        )));
    }

    #[test]
    fn rejects_non_pipe_handle() {
        let path = std::env::temp_dir().join(format!(
            "PhoneKey-server-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        assert!(verify_server(&file).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
