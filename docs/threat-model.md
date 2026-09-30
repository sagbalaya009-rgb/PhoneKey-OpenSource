# PhoneKey Threat Model

## Security boundary

PhoneKey adds a cryptographic authentication path; it does not replace Windows password, PIN, Windows Hello, disk encryption, Secure Boot, or TPM protections. The Android secure-lock credential and biometric processing remain inside Android security components. Windows receives protocol messages and signatures, not biometric templates or secure credentials.

The Credential Provider is a presentation and collection component. The custom LSA authentication package is the authority that evaluates the PhoneKey proof. The broker orchestrates sessions and BLE but must not be able to authorize a login merely because it received a QR scan or a Bluetooth connection.

## Adversary model

The design considers an attacker who can see or photograph the locked laptop screen, approach the laptop and attempt BLE connections, replay captured messages, possess a revoked phone, modify application-level files after gaining administrator access, send malformed BLE data, or steal the phone without knowing its secure-lock credential.

The system does not claim to protect against an attacker who already has SYSTEM- or LSA-level code execution. It is also not a remote authentication system and does not provide Windows-password recovery.

## Security objectives

| Objective | Required control |
|---|---|
| QR alone cannot authenticate | QR carries only a short-lived session; signing requires local Android authentication and a trusted private key |
| Replay resistance | Fresh laptop and phone nonces, short expiry, session binding, and atomic single-use consumption |
| Phone identity | Non-exportable Android Keystore signing key and stored public key; never trust device name, MAC, hostname, or installation ID |
| User presence/control | Android `BiometricPrompt` with strong biometric and/or `DEVICE_CREDENTIAL`; fresh authentication for every signing operation |
| Account correctness | Trusted-device record binds the phone to one explicit local Windows SID in v1 |
| Revocation | Local tombstone or disabled state; active sessions invalidated; revoked phones never accepted |
| Parser safety | Version checks, length validation, bounded allocations, integer-range checks, and fuzzing |
| Recovery | PhoneKey can be disabled independently; native Windows providers remain available; installation and uninstall are rollback-aware |
| Privacy | No PINs, passwords, patterns, biometric data, private keys, unnecessary signatures, raw nonce-bearing QR data, or full BLE packets in production logs |

## Key risks

The custom LSA package is the highest-impact component because native defects can affect logon availability. It must be introduced only after protocol and broker behavior are tested, first in a disposable VM, with a verified recovery path.

BLE interoperability is hardware- and driver-dependent. Windows GATT-server support must be tested on the ASUS adapter and driver, and Android behavior must be tested on the TECNO build. The credential-provider layout is controlled by Windows LogonUI, so QR readability inside a tile is a concrete usability and feasibility risk.

Android key invalidation after security-setting or biometric changes must be handled safely. The correct response is re-enrollment, never an automatic weakening of authentication requirements.

## Non-negotiable prohibitions

PhoneKey must not store or inject the Windows password into the standard password authentication package. It must not unregister native credential providers, turn off Windows recovery routes, accept Bluetooth pairing as identity, or silently downgrade cryptography or local user authentication to make a test pass.
