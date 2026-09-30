# Windows Native Components

The repository now contains the first native boundary for the Windows Credential Provider and LSA package.

## Implemented

The shared native code defines the fixed-width PhoneKey credential blob, including its magic, protocol version, session ID, phone ID, challenge hash, bounded signature, and flags. The serializer and defensive parser are covered by a portable C++ test that runs on Linux through CMake/CTest. The Credential Provider bridge refuses to serialize when PhoneKey is disabled and requests the proof from the broker rather than accepting a password or authorizing locally.

The native LSA-side parser validates input size, magic, version, signature length, and exact buffer boundaries before exposing fields. It is deliberately separate from the future signature/trust/session decision logic.

## Windows-only work remaining

The actual COM class factory and V2 `ICredentialProvider`/`ICredentialProviderCredential` implementation must be completed against the Windows SDK. It must enumerate no PhoneKey credentials when the persistent enable flag is off, render the session QR as a tile bitmap, request the broker proof, and return a package-specific serialization response for the PhoneKey authentication package.

The actual LSA package must implement the documented SSP/AP initialization and authentication-package entry points. It must perform the trust lookup, revocation check, session and SID binding checks, exact transcript reconstruction, ECDSA verification, atomic consume, and audit emission. No password-based MSV1_0 injection is permitted.

These components cannot be fully compiled or exercised in the current Linux sandbox because the Windows SDK, secure-desktop LogonUI, and LSA runtime are unavailable. They must be built and tested in a disposable Windows VM before installation on the ASUS laptop.
