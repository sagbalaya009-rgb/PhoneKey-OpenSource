# Security Policy

PhoneKey is experimental, security-sensitive authentication software.

A defect in the Windows service, BLE transport, enrollment flow, or Credential Provider can affect sign-in availability. Development of native sign-in changes must begin in a disposable Windows VM or dedicated test installation with a verified native Windows recovery path.

## Supported status

There is currently no production-supported consumer release.

The public repository contains experimental source and developer-preview build paths. Compatibility has not been established across all Windows versions, Bluetooth adapters, Android vendors, account types, or managed enterprise environments.

## Security invariants

Contributions must preserve these rules:

- Native Windows PIN/password/Windows Hello recovery must remain available during development and testing.
- PhoneKey must fail closed and remain independently disableable.
- Android signing/private keys must remain non-exportable where the platform supports it.
- Fresh local authentication must be required for each approval/signing operation.
- Phone biometric templates, PINs, passwords, or device-unlock secrets must never cross to Windows.
- Bluetooth names, MAC addresses, hostnames, and QR display text are not authentication identity.
- Revoked, consumed, mismatched, or expired sessions must be rejected.
- QR acceptance alone must never authorize sign-in; the matching fresh BLE challenge and signed proof are required.
- Untrusted inputs must be bounded and validated before parsing, allocation, cryptographic verification, or state transition.
- No secret, credential, private key, pairing state, protected database, or password vault may be committed to this repository or included in release assets.

## Reporting a vulnerability

Please do **not** open a public issue containing exploit details, credentials, raw authentication captures, pairing data, private keys, QR payloads, or protected state.

Use GitHub private vulnerability reporting when it is enabled for this repository. If that feature is temporarily unavailable, contact the repository owner privately through the contact method shown on the maintainer's GitHub profile.

Provide the smallest reproducible report possible and redact personal identifiers, credentials, tokens, device secrets, and private state.

## Public design versus pilot compatibility

Historical pilot testing used a locally protected Windows-password compatibility path for one explicitly authorized machine.

That pilot mechanism is not the target public authentication architecture and must not be described as passwordless.

See [docs/PUBLIC-WINDOWS-SIGNIN.md](docs/PUBLIC-WINDOWS-SIGNIN.md) for the current public-release gate.
