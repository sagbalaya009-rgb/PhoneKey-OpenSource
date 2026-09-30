# PhoneKey Architecture

> **Historical design proposal, not the current implementation.** The custom
> LSA authentication package, SQLite store, and passwordless account path
> described below have not been built. The current pilot uses the Rust
> LocalSystem service, native Credential Provider, Android BLE GATT server,
> protected JSON state, and an opt-in encrypted Windows-password vault after
> phone proof. See [CURRENT_STATE.md](CURRENT_STATE.md) and
> [PUBLIC-WINDOWS-SIGNIN.md](PUBLIC-WINDOWS-SIGNIN.md) before using this design.

## Scope

PhoneKey is a local authentication path spanning a generic Windows PC companion application, the Windows secure desktop, a Windows broker service, and a generic Android phone companion application. The two companion applications pair during enrollment; the pairing is represented by cryptographic installation identities, not by a laptop model, Android vendor, hostname, or Bluetooth address. The architecture deliberately separates presentation, orchestration, and authorization so that the Credential Provider is not treated as the security authority.

## Component boundaries

| Boundary | Component | Trust and responsibility |
|---|---|---|
| Secure desktop UI | V2 Windows Credential Provider | Renders the PhoneKey tile and QR bitmap, receives user interaction, requests session data, and serializes the returned proof. It does not decide authorization. |
| Authentication authority | Custom LSA authentication package | Parses the credential blob defensively, checks session and account binding, verifies the signature, atomically consumes the session, and returns the authentication result. |
| Local orchestration | Rust Windows broker service | Owns the GATT server, creates and expires sessions, coordinates phone messages, accesses the trust store, verifies protocol messages, and logs non-secret events. |
| Phone trust device | Android PhoneKey app | Scans QR sessions, displays the laptop identity, performs user authentication through Android APIs, signs the canonical transcript, and communicates over BLE. |
| Local administration | PhoneKey admin application | Performs privileged enable/disable, phone enrollment, revocation, diagnostics, and recovery actions. Management operations are separate from login-session operations. |
| Persistent state | SQLite and protected local configuration | Stores trusted-device metadata, bounded session state, settings, and audit events. It must not store Windows passwords, biometric data, or unnecessary signatures. |

## Normal authentication flow

```text
Windows LogonUI
    |
    | V2 Credential Provider requests a session
    v
Rust broker service
    |-- creates session_id, nonce_laptop, timestamps, and QR payload
    |-- advertises PhoneKey GATT service while enabled and healthy
    v
Windows Credential Provider displays QR
    |
    | phone scans QR and explicitly approves laptop identity
    v
Android PhoneKey app
    |-- connects as BLE GATT client
    |-- receives session details and nonce_phone challenge
    |-- invokes BiometricPrompt / device credential
    |-- signs canonical transcript using Android Keystore key
    v
Rust broker service
    |-- validates message, trust status, freshness, and session state
    |-- forwards compact proof to the authentication pipeline
    v
Custom LSA authentication package
    |-- validates credential blob and exact transcript
    |-- verifies ECDSA signature
    |-- binds trusted phone to explicit Windows SID
    |-- consumes session atomically
    v
Windows authorizes the bound local account
```

## IPC and service security

The broker runs as a Windows Service because PhoneKey must operate before interactive user logon. The Credential Provider and admin application communicate through constrained named-pipe interfaces with restrictive ACLs. The login-session interface must not expose trust-store mutation. Management methods are restricted to SYSTEM, the Credential Provider trust boundary where necessary, and administrators.

All requests from the phone are hostile until validated. The broker must enforce message-size, time, version, and state bounds. It must never execute arbitrary code supplied by the phone. A broker crash, service stop, or malformed request must result in an unavailable PhoneKey path rather than a stale authorization opportunity.

## Persistent data ownership

The broker owns session lifecycle and the local trust store. The Credential Provider should request only the information required to display and submit the current session. The LSA package should not become a general database client; its input must be a compact, bounded, package-specific credential blob and its validation path must be conservative.

The service has a SYSTEM-only redemption command for a verified Credential Provider session. It accepts the opaque transaction ID, returns the bound SID exactly once, and rejects pending, wrong-session, repeated, or expired redemption. Both wall-clock and monotonic deadlines bound this handoff. Redemption also rechecks that the trusted phone's device identity and public key, plus the account binding, are still present and unchanged; revocation after proof therefore blocks handoff. That original SID-only handoff does not authorize Windows logon. A custom authentication package remains an option for the public-release architecture, but protected LSA on the pilot laptop prevents loading an unsigned package. Keep native password and Windows Hello recovery available throughout testing.

For the one-laptop pilot, the user explicitly authorized a separate encrypted-password route because this Microsoft-account laptop runs protected LSA and cannot load an unsigned custom authentication package. The LocalSystem service has a service-account DPAPI vault, an administrator-only enrollment and rotation command restricted to the bound account SID, and a SYSTEM-only single-use release command after verified phone proof. The Credential Provider builds the standard online-identity credential from the qualified Microsoft-account name and releases it to Windows only after that command succeeds. Password entry happens locally through an interactive PowerShell prompt, never through chat or a command argument. This route has unlocked the target laptop after a live TECNO QR scan and fingerprint approval, including after a reboot. The service starts automatically. This pilot exception does not replace the public-release passwordless architecture above; native Windows sign-in remains available for recovery.

The first release binds each trusted phone to one explicit local Windows account SID on the Windows PC where it was enrolled. A Windows installation generates a stable random `laptop_id`; an Android installation generates a new cryptographic `phone_id` during enrollment. Phone identity is cryptographic and is not derived from a Bluetooth address, device name, hostname, or Android installation identifier. The same companion binaries can therefore enroll different PC/phone pairs without code changes.

## Lifecycle states

A login session progresses from `IDLE` to `CREATED`, `DISPLAYED`, `SCANNED`, `BLE_CONNECTED`, `PHONE_AUTHENTICATING`, `PHONE_AUTHENTICATED`, `SIGNATURE_RECEIVED`, `VERIFYING`, `AUTHORIZED`, and finally `CONSUMED`. Any state may fail; any pre-authorized state may expire; and cancellation must invalidate the session.

Enrollment progresses from QR scan through laptop verification, BLE connection, key creation, local authentication, proof submission, explicit user confirmation, and trust-record commit. Enablement progresses through `DISABLED`, `ENABLING`, `ENABLED`, `DISABLING`, and `SAFE_DISABLED` if a transition fails.

## Repository layout

The implementation is expected to evolve toward separate Android, Windows Credential Provider, Windows LSA, broker, admin, installer, shared protocol, test-vector, and end-to-end test directories. Shared protocol constants must have one canonical source of truth.
