//! Developer-only live protocol encoder/verifier. Never stores a phone key.

use phonekey_protocol::enrollment::{
    EnrollmentChallenge, decode_enrollment_challenge, decode_enrollment_proof, derive_pairing_code,
    encode_enrollment_challenge, verify_enrollment_proof,
};
use phonekey_protocol::messages::{
    LoginChallenge, LoginOperation, decode_login_challenge, encode_login_challenge,
};
use phonekey_protocol::proof::{decode_login_proof, verify_login_proof};
use phonekey_protocol::session::SessionStore;
use phonekey_protocol::types::{DeviceId, Nonce, SessionId};
use std::time::Instant;

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "wrong field length")?)
}

fn arg(args: &[String], index: usize) -> Result<&str, Box<dyn std::error::Error>> {
    Ok(args.get(index).ok_or("missing argument")?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match arg(&args, 1)? {
        "enrollment-challenge" => {
            let challenge = EnrollmentChallenge {
                windows_device_id: DeviceId(fixed(arg(&args, 2)?)?),
                enrollment_id: SessionId(fixed(arg(&args, 3)?)?),
                nonce: Nonce(fixed(arg(&args, 4)?)?),
                issued_at_ms: arg(&args, 5)?.parse()?,
                expires_at_ms: arg(&args, 6)?.parse()?,
            };
            println!("{}", hex::encode(encode_enrollment_challenge(&challenge)?));
        }
        "verify-enrollment" => {
            let challenge = decode_enrollment_challenge(&hex::decode(arg(&args, 2)?)?)?;
            let proof = decode_enrollment_proof(&hex::decode(arg(&args, 3)?)?)?;
            verify_enrollment_proof(&proof, &challenge)?;
            println!("ENROLLMENT_VALID");
            println!(
                "ANDROID_DEVICE_ID={}",
                hex::encode(proof.android_device_id.0)
            );
            println!("PUBLIC_KEY={}", hex::encode(proof.public_key_sec1));
            println!(
                "PAIRING_CODE={:06}",
                derive_pairing_code(&challenge, &proof)?
            );
        }
        "login-challenge" => {
            let challenge = LoginChallenge {
                windows_device_id: DeviceId(fixed(arg(&args, 2)?)?),
                session_id: SessionId(fixed(arg(&args, 3)?)?),
                nonce: Nonce(fixed(arg(&args, 4)?)?),
                issued_at_ms: arg(&args, 5)?.parse()?,
                expires_at_ms: arg(&args, 6)?.parse()?,
                operation: LoginOperation::Logon,
                account_binding: hex::decode(arg(&args, 7)?)?,
            };
            println!("{}", hex::encode(encode_login_challenge(&challenge)?));
        }
        "verify-login" => {
            let challenge = decode_login_challenge(&hex::decode(arg(&args, 2)?)?)?;
            let proof = decode_login_proof(&hex::decode(arg(&args, 3)?)?)?;
            let android_device_id = DeviceId(fixed(arg(&args, 4)?)?);
            let public_key = hex::decode(arg(&args, 5)?)?;
            verify_login_proof(&proof, &android_device_id, &public_key, &challenge)?;
            println!("LOGIN_PROOF_VALID");
        }
        "verify-login-session" => {
            let challenge = decode_login_challenge(&hex::decode(arg(&args, 2)?)?)?;
            let proof = decode_login_proof(&hex::decode(arg(&args, 3)?)?)?;
            let android_device_id = DeviceId(fixed(arg(&args, 4)?)?);
            let public_key = hex::decode(arg(&args, 5)?)?;
            let mut sessions = SessionStore::new();
            let monotonic = Instant::now();
            sessions.register_at(challenge.clone(), monotonic)?;
            let now_ms = challenge.issued_at_ms + 1;

            if sessions
                .verify_and_consume_at(
                    challenge.session_id,
                    &proof,
                    &android_device_id,
                    &public_key,
                    &challenge.windows_device_id,
                    b"wrong-account",
                    challenge.operation,
                    now_ms,
                    monotonic,
                )
                .is_ok()
            {
                return Err("proof accepted for wrong Windows account".into());
            }
            println!("WRONG_ACCOUNT_REJECTED");

            sessions.verify_and_consume_at(
                challenge.session_id,
                &proof,
                &android_device_id,
                &public_key,
                &challenge.windows_device_id,
                &challenge.account_binding,
                challenge.operation,
                now_ms,
                monotonic,
            )?;
            println!("SESSION_CONSUMED");

            if sessions
                .verify_and_consume_at(
                    challenge.session_id,
                    &proof,
                    &android_device_id,
                    &public_key,
                    &challenge.windows_device_id,
                    &challenge.account_binding,
                    challenge.operation,
                    now_ms,
                    monotonic,
                )
                .is_ok()
            {
                return Err("replayed proof was accepted".into());
            }
            println!("REPLAY_REJECTED");
        }
        "qr-pbm" => {
            let code = qrcode::QrCode::new(arg(&args, 2)?.as_bytes())?;
            let width = code.width();
            let modules = code.to_colors();
            let border = 4;
            let size = width + border * 2;
            let mut pbm = format!("P1\n{size} {size}\n");
            for y in 0..size {
                for x in 0..size {
                    let dark = x >= border
                        && y >= border
                        && x < width + border
                        && y < width + border
                        && modules[(y - border) * width + (x - border)] == qrcode::Color::Dark;
                    pbm.push(if dark { '1' } else { '0' });
                    pbm.push(' ');
                }
                pbm.push('\n');
            }
            std::fs::write(arg(&args, 3)?, pbm)?;
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}
