# Repository Guide

PhoneKey is organized by platform and security boundary.

| Path | Purpose |
|---|---|
| `windows/Cargo.toml` | Rust workspace |
| `windows/protocol/` | Canonical protocol, crypto, enrollment, session, proof, file-open primitives and tests |
| `windows/service/` | Privileged Rust Windows LocalSystem service |
| `windows/broker/` | Broker/admin and BLE diagnostic utilities |
| `windows/credential-provider/` | Native C++ Windows Credential Provider and transport tests |
| `windows/file-vault/` | Experimental PhoneKey Files implementation |
| `android/` | Android Studio companion application |
| `ios/` | iPhone companion source; not yet validated on physical Apple hardware |
| `docs/` | Architecture, security, build, test, roadmap and troubleshooting documentation |
| `.github/workflows/` | CI and manually triggered preview-release automation |

## Start here

1. `README.md`
2. `SECURITY.md`
3. `docs/ARCHITECTURE.md`
4. `docs/SECURITY_MODEL.md`
5. `docs/BUILD.md`
6. `docs/TESTING.md`
7. `docs/PUBLIC-WINDOWS-SIGNIN.md`
8. `docs/TROUBLESHOOTING.md`

## Source authority

The checked-in `main` branch of this public repository is the source tree intended for open-source development.

Generated binaries, pairing state, protected machine state, password vaults, signing keys, private recovery artifacts, and developer-machine databases are intentionally excluded from source control.

## Development principle

External platform boundaries remain authoritative:

- Windows LogonUI and the Windows authentication stack decide whether Windows accepts a credential.
- The privileged PhoneKey service owns PhoneKey authentication policy/state.
- Android/iOS platform key stores and local-authentication APIs protect phone-side signing keys.
- BLE is only a transport and must not be treated as identity.
