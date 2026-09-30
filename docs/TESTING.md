# PhoneKey Testing and Verification

> **Test plan, not a record of passed tests.** Many cases below remain release
> gates. Verified results and current device coverage are in
> [CURRENT_STATE.md](CURRENT_STATE.md) and
> [SHAREABLE-BUILD-STATUS.md](SHAREABLE-BUILD-STATUS.md).

Testing must proceed from low-risk protocol components toward the security-sensitive Windows authentication boundary. The LSA package must first be exercised in a disposable Windows VM or spare installation. Physical-device testing is required before production use because BLE, biometric capability, driver behavior, and credential-provider layout are platform-dependent.

## Protocol and crypto tests

The shared protocol tests must prove that canonical encoding is deterministic, field boundaries are unambiguous, and different session or nonce values produce different transcript hashes. Signature verification must accept only the exact valid signature and reject tampered payloads, wrong keys, wrong sessions, wrong operations, wrong SIDs, expired sessions, revoked devices, and replayed sessions.

All QR payload, BLE envelope, credential-blob, and LSA authentication-buffer parsers require fuzzing. Parsers that run in the LSA process must validate magic, version, lengths, caps, integer ranges, and pointer or allocation bounds before reading data.

## Android device tests

The Android application must first be tested on the currently available Android phone and then on at least one additional compatible Android phone. Required cases include successful fingerprint signing, cancellation without signing, device-PIN fallback, pattern/password fallback when exposed through `DEVICE_CREDENTIAL`, refusal to enroll or authenticate without a secure lock screen, safe handling of Android Keystore key invalidation, and clear recovery behavior when Bluetooth permissions are denied.

The app must show the laptop name and purpose before authentication, use the official `BiometricPrompt`, and never collect or persist biometric data or secure credentials.

## Windows component tests

The Windows suite must verify that the PhoneKey tile appears only when enabled, disappears or becomes inactive when disabled, regenerates QR data after expiry, and never removes native password, PIN, or Windows Hello providers. It must also verify that the BLE service is advertised only when enabled and healthy, that broker crashes do not leave stale authorizing credentials, that provider faults preserve native logon, and that revocation takes effect without reboot.

The one-laptop encrypted-password pilot additionally requires: SYSTEM-scoped vault round-trip with dummy data; administrator and bound-SID restrictions on provisioning; no password release before phone proof; single-use release before both deadlines; rejection after phone or account revocation; Microsoft-account credential packing; visible native-password fallback; and a real lock-screen sign-in with the enrolled TECNO. The host service, local vault, and tile are installed. The live lock-screen test and post-reboot sign-in succeeded after QR scan and TECNO fingerprint approval, and Windows opened automatically. The native PIN worked as fallback on an earlier unsuccessful attempt. Password rotation passed service tests with dummy data; a real password-change and refresh remains to be verified when the account password actually changes.

For the single-laptop login flow, verify that each QR is valid for exactly 60 seconds from service issuance, the QR dialog shows a live countdown from the service expiry, and the dialog closes at zero. Test an immediate scan, a scan near the deadline, an expired scan, and a phone clock trailing Windows slightly. The timer must not lengthen when Windows' wall clock moves backward. A successful signed phone proof is a separate milestone from an actual Windows unlock; both must be observed on the target laptop before calling the flow complete.

## Cross-device pairing matrix

Pairing is a first-class test dimension. The same companion application builds should enroll and authenticate the following combinations without code or configuration changes that identify a specific model:

| Windows companion | Android companion | Expected result |
|---|---|---|
| ASUS VivoBook | Current Android phone | Enrollment and authentication work if platform capabilities pass |
| Second compatible Windows PC | Same Android phone | Separate enrollment creates a separate Windows installation identity |
| ASUS VivoBook | Second compatible Android phone | Separate enrollment creates a separate phone identity |
| Second compatible Windows PC | Second compatible Android phone | Independent pairing and authentication work |
| Any revoked phone | Previously enrolled Windows PC | Authentication is rejected immediately |

A phone enrolled to one Windows installation must not authenticate to another installation unless it is explicitly enrolled there. A replacement phone is a new cryptographic identity even if it has the same display name or Bluetooth address.

## End-to-end matrix

| Scenario | Expected result |
|---|---|
| Fresh trusted phone with fingerprint | Success |
| Fresh trusted phone with PIN, pattern, or password | Success where Android exposes `DEVICE_CREDENTIAL` capability |
| Untrusted phone | Reject |
| Revoked phone | Reject |
| Expired QR | Reject |
| Replayed signature | Reject |
| QR created for another laptop | Reject |
| BLE disconnect before signing | Safe rejection |
| BLE disconnect after signing before receipt | Reject or retry only when the transaction remains valid and non-replayed |
| PhoneKey disabled | No PhoneKey authentication; native login works |
| Broker unavailable | PhoneKey unavailable; native login works |
| Credential Provider fault | Native login works |
| Malformed BLE packet | Reject connection or session without crash |
| Workstation unlock | Validate independently from boot logon |

## Release gate

The project is not complete until it builds from a fresh checkout with documented tool versions, installs on the target Android device, creates a non-exportable Android Keystore key, supports the available local-authentication routes, displays and expires a Windows QR session, completes BLE exchange, verifies the correct trusted public key and SID binding, rejects replay and revocation, preserves native recovery, and uninstalls safely. Security-sensitive modules must document assumptions and threat coverage.
