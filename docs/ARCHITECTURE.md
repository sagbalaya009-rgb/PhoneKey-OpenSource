# PhoneKey Architecture

PhoneKey is a local phone-approved Windows authentication system. The current implementation separates discovery/transport, user approval, privileged authentication state, and Windows credential submission so that no single UI component becomes the security authority.

## Current implementation

```text
Android companion
  │
  │ BLE advertisement + GATT
  │ signed challenge/proof
  ▼
PhoneKey Windows service
(Rust, LocalSystem)
  │
  │ restricted named-pipe IPC
  ▼
Native Windows Credential Provider
  │
  ▼
Windows LogonUI / Windows authentication stack
```

The Android application currently acts as the BLE GATT peripheral/server for the Windows sign-in path. The Windows service discovers the PhoneKey service, connects, delivers a fresh login challenge, and reads the signed proof after local phone authentication.

## Security boundaries

| Boundary | Component | Responsibility |
|---|---|---|
| Phone local trust | Android companion | Holds the phone signing identity, validates QR/challenge binding, requires local authentication, signs the canonical proof |
| Untrusted transport | BLE | Discovery and message transport only; Bluetooth metadata is never authentication identity |
| Privileged authority | Rust Windows service | Owns enrollment, trusted-phone state, login sessions, BLE orchestration, account binding, proof verification and one-use authorization |
| Secure desktop integration | Native Credential Provider | Displays PhoneKey status/QR, communicates with the service, and hands the permitted credential form to Windows |
| Final OS decision | Windows authentication stack | Makes the final Windows logon decision |
| Recovery | Native Windows providers | PIN/password/Windows Hello remain available during development and testing |

## Login flow

1. Windows LogonUI selects the PhoneKey Credential Provider.
2. The provider asks the privileged service to create a bounded login transaction.
3. The service creates the fresh session/challenge and exposes the QR/bootstrap material.
4. The phone scans the QR and starts/refreshes PhoneKey BLE advertising.
5. Windows discovers the PhoneKey BLE service and connects.
6. Windows delivers the exact fresh login challenge over GATT.
7. The Android app verifies that the BLE challenge matches the scanned QR/session.
8. Android waits until the app is foregrounded/focused, then invokes local biometric/device authentication.
9. The phone signs the canonical login transcript with its enrolled key.
10. Windows reads the proof and the privileged service verifies trust, freshness, signature, account binding, expiry and one-use state.
11. Only after verification does the Credential Provider receive the bounded authorization/credential material needed for Windows sign-in.
12. Windows performs the final credential acceptance/rejection.

## Enrollment

Enrollment establishes a cryptographic phone identity, not a Bluetooth identity.

The trust record binds:

- a PhoneKey phone identity/public key;
- the Windows-side installation/account context;
- explicit enrollment confirmation.

Bluetooth addresses, device names, hostnames, and model names are not trusted identities.

If the Android application is uninstalled or its app-private key material is destroyed, the replacement installation is a new cryptographic identity and must be enrolled again.

## IPC boundary

The Windows service runs in a privileged context and communicates with the Credential Provider/admin tools through constrained local IPC.

The service, not the Credential Provider UI, owns policy decisions. IPC input is treated as untrusted, bounded, validated, and tied to explicit transaction state.

## Current pilot credential bridge

The tested single-laptop pilot uses a locally protected encrypted Windows-password compatibility bridge after verified phone proof.

That mechanism:

- stays on the Windows machine;
- is not sent to the phone;
- is protected behind the privileged service;
- is released only through the bounded verified transaction path;
- is not the desired general public passwordless architecture.

See [PUBLIC-WINDOWS-SIGNIN.md](PUBLIC-WINDOWS-SIGNIN.md).

## Observability

PhoneKey records privacy-safe event stages/timings for debugging. Diagnostics are designed to avoid logging:

- passwords;
- QR payloads;
- private keys;
- proof bytes;
- account names/SIDs.

BLE troubleshooting and timing-stage interpretation are documented in [BLE-TRANSPORT-TROUBLESHOOTING.md](BLE-TRANSPORT-TROUBLESHOOTING.md).

## Failure behavior

PhoneKey should fail closed.

A stalled BLE connection, expired challenge, mismatched QR/challenge, invalid signature, revoked phone, wrong account binding, unavailable service, malformed IPC request, or consumed transaction must not authorize sign-in.

Native Windows recovery providers remain mandatory while PhoneKey is experimental.
