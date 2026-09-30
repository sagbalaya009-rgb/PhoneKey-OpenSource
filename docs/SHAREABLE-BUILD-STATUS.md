## GitHub preview downloads

A dedicated preview-release workflow now builds and tests both platforms on GitHub-hosted runners. A release is published only after the Windows Rust tests/build, Credential Provider build, Android unit tests/build, and source-safety checks complete successfully. The release assets are `PhoneKey-Android-Preview.apk`, `PhoneKey-Windows-Preview.zip`, and `SHA256SUMS.txt`.

These releases are developer previews, not a declaration of public-release readiness. The Android APK is debug-signed. The Windows ZIP is for a disposable VM or dedicated test PC and is not a safe one-click installer for an everyday Windows machine.

# Windows + Android sharing status

The Windows 11 x64 service EXE, native Credential Provider DLL, broker EXE,
and Android debug APK build from this source. The APK supports Android 8.0+
at the manifest level, but a usable phone also needs Bluetooth LE peripheral
advertising, a screen lock/biometric or device credential, Bluetooth permission,
and QR scanning. Compatibility has been verified only on the enrolled TECNO
SPARK 30C and this Windows 11 laptop. Other PCs, Bluetooth adapters, Android
vendors, account types, and Windows versions have not been verified.

The Windows EXE is a service component, **not an installer**. The working
single-laptop pilot uses a privileged service, a Credential Provider DLL,
protected state, enrollment, and an opt-in encrypted Microsoft-account password
vault. Copying or double-clicking an EXE cannot reproduce that setup. Do not
install these preview binaries on another person's everyday PC. A reviewed,
signed installer, safe uninstall and recovery, second-PC tests, account support,
and independent security review remain before general distribution. Public
Microsoft-account support is held pending a supported passwordless Windows
route. The current pilot's PIN/password fallback remains available.

To recreate the preview files on a Windows development machine, build the Rust
service and broker, native x64 Credential Provider, and Android debug APK using
[BUILD.md](BUILD.md). Then run
`windows\Build-PhoneKeyPreview.ps1` in PowerShell. The script copies only built
Windows binaries into ignored `dist/PhoneKey-Windows-Preview/`, writes SHA-256
checksums, and makes `dist/PhoneKey-Windows-Preview.zip`. The Android test APK is
`android/app/build/outputs/apk/debug/app-debug.apk`. Its debug signing key is
local to the builder; it is not a stable release identity and cannot update an
installation signed by another key. Neither preview is a public release.

The iPhone source is separate and remains uncompiled until a Mac and physical
iPhone are available. The installed laptop sign-in and its TECNO pairing were
not changed to make these build outputs.
