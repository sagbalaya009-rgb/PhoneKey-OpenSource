# Build From Zero

## Prerequisites

### Windows development
- Windows 11 x64
- Git
- Rust stable + Cargo
- Visual Studio 2022 / Build Tools
- MSVC v143 C++ toolset
- Windows 10/11 SDK
- PowerShell 5.1+ or PowerShell 7

The recovered Rust workspace uses Rust edition 2024.

### Android
- Android Studio / Android SDK
- compatible JDK
- the checked-in Gradle wrapper

## Windows Rust workspace

```powershell
cd windows
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Workspace members: `protocol`, `broker`, `service`.

## Credential Provider transport tests

On a Visual Studio Developer PowerShell:

```powershell
msbuild windows\credential-provider\tests\PhoneKeyTransportLifetimeFixture.vcxproj /m /p:Configuration=Release /p:Platform=x64
msbuild windows\credential-provider\tests\PhoneKeyTransportTests.vcxproj /m /p:Configuration=Release /p:Platform=x64
```

Locate and execute `PhoneKeyTransportTests.exe`. Do not register the Credential Provider merely to run transport tests.

## Credential Provider

Use `windows\credential-provider\SampleV2CredentialProvider.sln` and build x64. Registration/secure-desktop testing belongs only in a disposable Windows VM with rollback prepared.

## Android

```powershell
cd android
.\gradlew.bat test
.\gradlew.bat assembleDebug
```

On Linux/macOS use `./gradlew`.

## Output policy

Do not commit normal build outputs, IDE caches, `local.properties`, real machine/pairing/enrollment state, keys or credentials. Recovery archives under `recovery/archives/` are intentional checksum-indexed historical artifacts. The two explicitly labelled, checksum-indexed developer-preview binaries under `dist/` are a one-time exception requested for sharing; they are not release installers and contain no enrolled state.

## Guarded Windows installer source

`windows/installer/Build-PhoneKeyInstaller.ps1` builds a setup preview from
locally built release service/broker and x64 Credential Provider components.
Run the resulting EXE with `--preflight` for a read-only prerequisite check.
This public repository contains installer source, not a newly verified release
binary. The preview supports clean Windows 11 x64 local-account PCs, stages
the service with the sign-in tile disabled, and enables the tile only after
pairing and local-account password enrollment. It refuses an existing PhoneKey
installation and Microsoft-account profiles. Clean-PC installation, pairing,
sign-in and uninstall remain unverified; do not treat the six pilot sign-ins
as installer validation. The setup preview has not been rebuilt with the latest
BLE fixes during this investigation.
