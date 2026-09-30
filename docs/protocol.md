# PhoneKey Protocol

## Protocol rules

The protocol must use one deterministic canonical encoding for every signed field. Variable-length values are length-prefixed or encoded by a canonical schema; ambiguous string concatenation is prohibited. The protocol version, constants, UUIDs, and error codes must be centralized in the shared protocol module.

The baseline signing algorithm is **ECDSA P-256 with SHA-256**. The phone generates the private key in Android Keystore with export prohibited. Windows stores the public key and device metadata only.

## Portable pairing model

PhoneKey is not locked to the ASUS VivoBook, a TECNO phone, or any other specific hardware. The Windows companion creates a stable random `laptop_id` once per Windows installation. The Android companion creates a new `phone_id` and a non-exportable signing key for each enrollment. The Windows trust store records the phone public key, display name, and explicit local Windows SID binding. A replacement phone is always enrolled as a new cryptographic identity.

Bluetooth addresses, device names, hostnames, Android installation IDs, and hardware models are discovery or display metadata only. They must never authorize a login or silently reconnect a revoked identity. The QR session carries the current Windows installation identity and a short-lived challenge so the same application binaries can pair with any compatible Windows PC and Android phone.

## Authentication transcript

The signature input is the canonical encoding of the following ordered fields:

```text
protocol_version ||
laptop_id ||
phone_id ||
session_id ||
nonce_laptop ||
nonce_phone ||
issued_at ||
expires_at ||
operation ||
account_binding ||
transcript_hash
```

The implementation must define the exact types, lengths, byte order, and canonical representation for every field. The transcript must be identical on Android and Windows, with fixed test vectors for encoding, hashing, signing, and verification.

| Value | Size | Origin | Purpose |
|---|---:|---|---|
| `session_id` | 16 bytes | Laptop CSPRNG | Identifies one login attempt |
| `nonce_laptop` | 32 bytes | Laptop CSPRNG | Prevents replay and prediction |
| `nonce_phone` | 32 bytes | Phone CSPRNG | Adds mutual freshness |
| `challenge_hash` | 32 bytes | SHA-256 | Binds the transcript |

Windows must look up the phone by its cryptographic `phone_id`, confirm that it is trusted and not revoked, reconstruct the exact transcript, verify the ECDSA signature, and only then consume the session nonce atomically. A valid signature from an expired, revoked, wrong-SID, or wrong-operation context remains invalid.

## QR session payload

The QR payload uses the versioned form below:

```text
PHONEKEY1.<base64url(canonical_cbor({
  v: 1,
  laptop_id: bytes,
  session_id: bytes,
  nonce_laptop: bytes,
  issued_at: uint64,
  expires_at: uint64,
  ble_service_uuid: uuid,
  ble_hint: optional,
  label: string
}))>
```

The QR is a transport for a short-lived session, not an authentication factor by itself. It must not contain passwords, private keys, unnecessary certificates, or other long-lived secrets. The recommended lifetime is approximately 60 seconds. The broker must invalidate it after successful authentication or explicit cancellation.

The phone validates the prefix and version, expiry, laptop identity format, session and nonce lengths, expected PhoneKey service UUID, and consumed/cancelled state. Before connecting, it displays the human-readable laptop name and requires explicit user approval.

## BLE GATT service

Windows acts as the GATT server/peripheral and Android acts as the GATT client/central. The application-layer signature is mandatory; Bluetooth pairing or link encryption is only defense in depth.

| Item | UUID or property |
|---|---|
| PhoneKey service | `0000f001-0000-1000-8000-00805f9b34fb` |
| Session characteristic | `0000f002-0000-1000-8000-00805f9b34fb`; `READ / NOTIFY` |
| Request characteristic | `0000f003-0000-1000-8000-00805f9b34fb`; `WRITE / WRITE_NO_RESPONSE` |
| Response characteristic | `0000f004-0000-1000-8000-00805f9b34fb`; `WRITE / NOTIFY` |

All BLE messages use a bounded envelope:

```text
version       : u8
message_type  : u8
request_id    : 16 bytes
payload_length: u16 or u32
payload       : bytes
mac_or_signature: optional, depending on protocol stage
```

Every parser must validate the version, message type, declared length, maximum allocation, request state, and timeout before reading or allocating payload data.

## Android authentication requirements

The app must use Android `BiometricPrompt`, not a custom fingerprint interface. Where supported by the target Android build, the logical authenticator policy is:

```text
ALLOW = BIOMETRIC_STRONG | DEVICE_CREDENTIAL
KEY USE = fresh user authentication required
TIMEOUT = 0 seconds
PRIVATE KEY = Android Keystore, non-exportable
SIGNATURE = ECDSA P-256 / SHA-256
```

The signing operation must use a `CryptoObject`. A cancelled or failed prompt must abort the pending operation. No biometric template or secure credential is captured or stored by PhoneKey.

## Windows credential blob

The Credential Provider submits a package-specific blob rather than a password:

```text
PhoneKeyCredentialBlob v1:
  magic[8] = "PHKEY\\x00\\x01"
  version u16
  session_id[16]
  phone_id[16]
  challenge_hash[32]
  signature_length u16
  signature[variable]
  flags u32
  reserved...
```

The LSA package must validate the magic, version, lengths, caps, reserved fields, session state, phone status, exact SID binding, operation binding, freshness, signature, and atomic session-consumption result. The blob must never contain a Windows password.

## Error and replay behavior

The protocol returns structured errors without revealing sensitive internal details. Replayed signatures, expired sessions, revoked devices, wrong-laptop QR payloads, malformed packets, wrong account bindings, and mismatched transcripts must all be rejected. A retry is allowed only when the session remains valid and the prior attempt did not consume it.
