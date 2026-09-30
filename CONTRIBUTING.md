# Contributing to PhoneKey

PhoneKey is security-sensitive Windows authentication software. Contributions are welcome, but changes to authentication, enrollment, IPC, BLE transport, protected state, or the Credential Provider require extra care.

## Before opening a pull request

- Read [SECURITY.md](SECURITY.md), [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md), and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Keep native Windows recovery providers enabled.
- Test native Windows sign-in changes in a disposable VM or dedicated test installation first.
- Never commit credentials, private keys, pairing secrets, protected state, password vaults, machine databases, crash dumps, or signing keystores.
- Run formatting, static checks, and tests for each component you change.
- Document protocol/state/schema changes and their migration or recovery behavior.
- Prefer small, reviewable commits.
- Do not weaken authentication checks merely to make a test pass.

## Component guidance

### Windows service and protocol

The Rust service owns privileged policy and authentication state. Keep authorization decisions out of UI code.

### Credential Provider

Keep the provider thin. It should transport status and credential material only after the privileged service has completed the required verification.

### Android

Private signing keys should remain non-exportable and user-auth gated. Do not log QR payloads, private key material, or signed proof bytes.

### BLE

Treat BLE as a hostile transport. Device names, addresses, pairing metadata, and advertisement presence are discovery signals, not authorization.

## Pull requests

A useful pull request should include:

- a concise description of the behavior being changed;
- security implications, if any;
- tests added or updated;
- manual verification steps when platform integration is involved;
- rollback/recovery considerations for Windows sign-in changes.

## Security issues

Do not disclose vulnerabilities in ordinary public issues. Follow [SECURITY.md](SECURITY.md).
