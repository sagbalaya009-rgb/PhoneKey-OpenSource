use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

const PUBLIC_KEY_HEX: &str = "0455028fa482aa8203d0388504cf044142703aff3\
6994dbc8985349b30e9c6ddccf5b5f747840e1f97\
aca626aaa23258e071510f36fbc792cf6540506bf65da1a7";

const SIGNATURE_HEX: &str = "59c82efb0ca9a1870cdd157d42210b0d5a03e699\
7c0092eb7f896926100c680471fa4bd1b1e56d7c4\
7951d9566e903ed63674f7bca23ebef1286a1ec1b292bb4";

const CHALLENGE_HEX: &str = "a901010201\
035011111111111111111111111111111111\
045022222222222222222222222222222222\
0558203333333333333333333333333333333333333333333333333333333333333333\
061a000f4240\
071a00102ca0\
0801\
0958204444444444444444444444444444444444444444444444444444444444444444";

const SIGNING_DOMAIN: &[u8] = b"PHONEKEY-LOGIN-SIGNATURE-V1\0";

#[test]
fn verifies_real_android_keystore_signature() {
    let public_key_bytes = hex::decode(PUBLIC_KEY_HEX).expect("public key hex must decode");

    let signature_bytes = hex::decode(SIGNATURE_HEX).expect("signature hex must decode");

    let challenge_bytes = hex::decode(CHALLENGE_HEX).expect("challenge hex must decode");

    assert_eq!(
        public_key_bytes.len(),
        65,
        "P-256 SEC1 public key must be 65 bytes"
    );

    assert_eq!(
        signature_bytes.len(),
        64,
        "PhoneKey P-256 signature must be 64 bytes"
    );

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .expect("Android public key must be a valid P-256 key");

    let signature =
        Signature::from_slice(&signature_bytes).expect("Android signature must be valid raw r||s");

    let mut transcript = Vec::with_capacity(SIGNING_DOMAIN.len() + challenge_bytes.len());

    transcript.extend_from_slice(SIGNING_DOMAIN);

    transcript.extend_from_slice(&challenge_bytes);

    verifying_key
        .verify(&transcript, &signature)
        .expect("Rust failed to verify the Android Keystore signature");
}
