# PhoneKey

PhoneKey is an open-source experimental system for **phone-approved Windows 11 sign-in over Bluetooth Low Energy (BLE)**.

The current implementation combines:

- an Android companion app;
- a Rust Windows LocalSystem service;
- a native Windows Credential Provider;
- a security-focused signed challenge/proof protocol;
- BLE transport and enrollment flows;
- automated Rust, Android, and native C++ tests;
- an experimental PhoneKey Files subsystem.

> **Important:** PhoneKey is security-sensitive experimental software. The source is public for development, review, research, and collaboration. The current Windows preview is **not** a production installer and should not be deployed to an everyday PC without a tested native Windows recovery path.

## Architecture

```text
Android phone
  │
  │ BLE + signed challenge/proof
  ▼
PhoneKey Windows service
(Rust, LocalSystem)
  │
  │ restricted local IPC
  ▼
Native Windows Credential Provider
  │
  ▼
Windows Logon UI
```

The privileged Windows service owns the authentication state machine, BLE orchestration, trust/account binding, enrollment authority, protected state, and login authorization. The Credential Provider is intentionally kept thin.

## Source layout

```text
android/                       Android companion application
ios/                           iPhone companion source (not yet device-tested)
windows/
  service/                     Rust LocalSystem Windows service
  protocol/                    protocol, crypto, sessions, proofs, tests
  broker/                      broker/admin and BLE utilities
  credential-provider/         native C++ Credential Provider
  file-vault/                  experimental PhoneKey Files subsystem
docs/                          architecture, security, build and test docs
.github/workflows/             CI and preview-release automation
```

Start with:

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Build guide](docs/BUILD.md)
- [Testing guide](docs/TESTING.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Roadmap](docs/ROADMAP.md)
- [Current public Windows sign-in gate](docs/PUBLIC-WINDOWS-SIGNIN.md)

## Current maturity

The project has completed real pilot QR + biometric + Windows unlock testing on one Windows 11 laptop and one Android phone. The repository also contains automated tests across the Rust protocol/service code, Android companion, and native Credential Provider transport.

That does **not** establish broad compatibility across Windows builds, Bluetooth adapters, Android vendors, account types, or enterprise environments.

The public-release architecture remains stricter than the original pilot compatibility path. In particular, the long-term public design should not require PhoneKey to retain each user's Microsoft-account password.

## Build and test

Windows native integration requires Windows 11, Rust, MSVC/Visual Studio Build Tools, and the Windows SDK. The Android app requires Android Studio/Gradle tooling.

See [docs/BUILD.md](docs/BUILD.md) for the exact component build steps and [docs/TESTING.md](docs/TESTING.md) for the safety gates.

For native sign-in experiments:

1. use a disposable Windows VM or dedicated test installation;
2. keep Windows PIN/password/Hello recovery available;
3. do not disable native Windows recovery providers;
4. validate rollback before installing a Credential Provider build.

## Security

PhoneKey handles privileged Windows authentication state. Please read [SECURITY.md](SECURITY.md) before testing or contributing.

Never publish:

- credentials or password-vault contents;
- private keys or Android Keystore material;
- raw pairing secrets;
- full authentication transcripts;
- private QR payloads;
- protected machine state;
- personal machine databases or crash dumps.

Security reports should use GitHub private vulnerability reporting when available rather than public issues.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Security-sensitive changes should be small, reviewable, test-backed, and preserve native Windows recovery paths.

## License

PhoneKey is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2026 PhoneKey contributors.
