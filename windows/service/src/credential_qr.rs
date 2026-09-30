use phonekey_protocol::types::{DeviceId, SessionId};
use qrcode::{QrCode, types::Color};
use std::io;

pub const BEGIN_RESPONSE_VERSION: u8 = 2;

const QR_PREFIX: &str = "PK1";
const QR_TEXT_LENGTH: usize = 86;

const MIN_QR_WIDTH: usize = 21;
const MAX_QR_WIDTH: usize = 177;

const MAX_BEGIN_RESPONSE_BYTES: usize = 2_048;

pub fn bootstrap_text(
    windows_device_id: &DeviceId,
    session_id: &SessionId,
    expires_at_ms: u64,
) -> io::Result<String> {
    if windows_device_id.0.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other(
            "PhoneKey Windows device ID cannot be zero",
        ));
    }

    if session_id.0.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other("PhoneKey session ID cannot be zero"));
    }

    let text = format!(
        "{QR_PREFIX}|{}|{}|{expires_at_ms:016x}",
        encode_hex(&windows_device_id.0),
        encode_hex(&session_id.0),
    );

    if text.len() != QR_TEXT_LENGTH {
        return Err(io::Error::other("PhoneKey QR bootstrap is not canonical"));
    }

    Ok(text)
}

pub fn encode_begin_response(
    windows_device_id: &DeviceId,
    session_id: &SessionId,
    expires_at_ms: u64,
) -> io::Result<Vec<u8>> {
    let text = bootstrap_text(windows_device_id, session_id, expires_at_ms)?;

    let code = QrCode::new(text.as_bytes())
        .map_err(|error| io::Error::other(format!("PhoneKey QR generation failed: {error}",)))?;

    let width = code.width();

    if !(MIN_QR_WIDTH..=MAX_QR_WIDTH).contains(&width) || !(width - MIN_QR_WIDTH).is_multiple_of(4)
    {
        return Err(io::Error::other("PhoneKey QR width is invalid"));
    }

    let modules = code.to_colors();

    let module_count = width
        .checked_mul(width)
        .ok_or_else(|| io::Error::other("PhoneKey QR size overflow"))?;

    if modules.len() != module_count {
        return Err(io::Error::other("PhoneKey QR module count mismatch"));
    }

    let mut packed = vec![0u8; module_count.div_ceil(8)];

    for (index, module) in modules.into_iter().enumerate() {
        if module == Color::Dark {
            packed[index / 8] |= 1u8 << (7 - (index % 8));
        }
    }

    let width = u8::try_from(width).map_err(|_| io::Error::other("PhoneKey QR width overflow"))?;

    /*
     * BeginCredentialProviderLogin response:
     *
     * byte 0      schema version
     * bytes 1-16  opaque transaction ID
     * byte 17     QR width
     * bytes 18-25 absolute QR expiry (Unix milliseconds, big endian)
     * bytes 26+   packed QR modules
     *
     * The raw LoginChallenge remains inside PhoneKeyService.
     */
    let mut response = Vec::with_capacity(26 + packed.len());

    response.push(BEGIN_RESPONSE_VERSION);
    response.extend_from_slice(&session_id.0);
    response.push(width);
    response.extend_from_slice(&expires_at_ms.to_be_bytes());
    response.extend_from_slice(&packed);

    if response.len() > MAX_BEGIN_RESPONSE_BYTES {
        return Err(io::Error::other("PhoneKey QR response exceeds IPC limit"));
    }

    Ok(response)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);

        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceId {
        DeviceId([0x11; 16])
    }

    fn session() -> SessionId {
        SessionId([0x22; 16])
    }

    #[test]
    fn bootstrap_is_exact_and_canonical() {
        let text = bootstrap_text(&device(), &session(), 0x0000_019a_bc12_3456).unwrap();

        assert_eq!(text.len(), QR_TEXT_LENGTH,);

        assert_eq!(
            text,
            "PK1|11111111111111111111111111111111|22222222222222222222222222222222|0000019abc123456",
        );
    }

    #[test]
    fn zero_windows_device_is_rejected() {
        assert!(bootstrap_text(&DeviceId([0; 16]), &session(), 123,).is_err());
    }

    #[test]
    fn zero_session_is_rejected() {
        assert!(bootstrap_text(&device(), &SessionId([0; 16]), 123,).is_err());
    }

    #[test]
    fn begin_response_contains_transaction_and_bounded_qr() {
        let session = session();

        let response = encode_begin_response(&device(), &session, 0x0000_019a_bc12_3456).unwrap();

        assert_eq!(response[0], BEGIN_RESPONSE_VERSION,);

        assert_eq!(&response[1..17], &session.0,);

        let width = response[17] as usize;

        assert!((MIN_QR_WIDTH..=MAX_QR_WIDTH).contains(&width));

        assert!((width - MIN_QR_WIDTH).is_multiple_of(4));

        assert_eq!(
            u64::from_be_bytes(response[18..26].try_into().unwrap()),
            0x0000_019a_bc12_3456
        );

        assert_eq!(response.len(), 26 + (width * width).div_ceil(8));

        assert!(response.len() <= MAX_BEGIN_RESPONSE_BYTES);
    }

    #[test]
    fn packed_modules_match_generated_qr() {
        let text = bootstrap_text(&device(), &session(), 0x0000_019a_bc12_3456).unwrap();

        let expected = QrCode::new(text.as_bytes()).unwrap();

        let expected_modules = expected.to_colors();

        let response = encode_begin_response(&device(), &session(), 0x0000_019a_bc12_3456).unwrap();

        let width = response[17] as usize;

        assert_eq!(width, expected.width(),);

        let packed = &response[26..];

        for (index, expected_module) in expected_modules.iter().enumerate() {
            let actual_dark = (packed[index / 8] & (1u8 << (7 - (index % 8)))) != 0;

            assert_eq!(
                actual_dark,
                *expected_module == Color::Dark,
                "QR module mismatch at index {index}",
            );
        }
    }
}
