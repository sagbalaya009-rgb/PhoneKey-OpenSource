# Roadmap

PhoneKey is open source, but the current developer previews are not yet a production consumer release.

## Current — public source and reproducible validation

- Keep Windows Rust workspace checks/tests green.
- Keep native Credential Provider transport/lifetime tests green.
- Keep Android unit tests and debug builds green.
- Keep source-safety and secret-scanning gates enabled.
- Maintain clear separation between the tested pilot compatibility path and the intended public authentication architecture.

## Next — Windows release engineering

- Build a reviewed installer/uninstaller with deterministic rollback.
- Add stable code signing for Windows components.
- Validate install, update, disable, uninstall, and Windows Update recovery.
- Expand negative LogonUI tests for service crash, BLE loss, cancellation, expiry, replay, account mismatch, and corrupted state.
- Test across multiple Windows 11 machines and Bluetooth adapters.

## Next — broader Android/BLE compatibility

- Test multiple Android vendors and OS versions.
- Measure BLE discovery/connection/GATT reliability across common chipsets.
- Validate permission, backgrounding, biometric interruption, screen rotation, and reconnect behavior.
- Establish a documented supported-device capability matrix.

## Public authentication architecture

The current pilot can bridge verified phone approval into ordinary Windows credentials using locally protected state. That compatibility path is not the desired general consumer architecture.

Before calling PhoneKey a general public Windows sign-in product:

- define a supported Windows authentication route for each advertised account type;
- avoid presenting the pilot password-vault bridge as passwordless;
- verify recovery and account-transition behavior;
- complete independent security review.

See [PUBLIC-WINDOWS-SIGNIN.md](PUBLIC-WINDOWS-SIGNIN.md).

## PhoneKey Files

Continue hardening the experimental file-vault path:

- physical-device testing across larger files;
- key lifecycle/recovery UX;
- tamper/corruption handling;
- Windows shell integration safety;
- independent review before real-document recommendations.

## iOS

- build the current source on macOS;
- run unit tests;
- validate on a physical iPhone;
- verify BLE behavior against a clean Windows test environment;
- do not claim iOS compatibility until those tests pass.

## Not yet

- broad consumer deployment;
- removal of native Windows recovery providers;
- enterprise AD/Entra support claims;
- production compatibility claims without a tested device/account matrix.
