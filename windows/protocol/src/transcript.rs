use crate::error::ProtocolError;
use crate::messages::{LoginChallenge, encode_login_challenge};

const LOGIN_SIGNATURE_DOMAIN: &[u8] = b"PHONEKEY-LOGIN-SIGNATURE-V1\x00";

pub fn login_signature_transcript(challenge: &LoginChallenge) -> Result<Vec<u8>, ProtocolError> {
    let encoded_challenge = encode_login_challenge(challenge)?;

    let mut transcript = Vec::with_capacity(LOGIN_SIGNATURE_DOMAIN.len() + encoded_challenge.len());

    transcript.extend_from_slice(LOGIN_SIGNATURE_DOMAIN);
    transcript.extend_from_slice(&encoded_challenge);

    Ok(transcript)
}
