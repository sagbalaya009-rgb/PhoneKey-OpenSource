# Roadmap

## COMPLETE / PRESERVED

- August GitHub baseline preserved in history.
- Original implementation specification preserved.
- September Windows Stage-E source recovered.
- Local Stage-D → Stage-E Git history preserved as a portable bundle.
- Android Studio source recovered.
- September recovery/source artifacts preserved with SHA-256 manifests.
- Canonical recovered source reconstructed into normal `windows/` and `android/` paths.
- Repository documentation updated to the recovered architecture.

## NEXT: REPRODUCIBLE VALIDATION

- Windows Rust workspace fmt/check/test/clippy.
- Native Credential Provider transport/lifetime build and test.
- Android unit tests and debug build.
- Review CI failures against the recovered historical environment rather than altering security semantics merely to make CI green.

## NEXT: DISPOSABLE WINDOWS VM

- build service + CP from exact GitHub commit;
- install service and confirm Running / Auto / LocalSystem;
- verify named-pipe ACL/ownership and unauthorized-caller rejection;
- register/unregister CP;
- verify tile stability under Win+L;
- validate timeout/cancellation/crash paths;
- verify rollback and native Windows recovery provider availability.

## NEXT: REAL ANDROID + BLE

- install companion app on a physical Android phone;
- test BLE from LocalSystem service context;
- perform enrollment;
- verify trusted pairing/account binding;
- challenge/proof happy path;
- replay/stale/wrong-device/wrong-account negatives;
- reboot/persistence/revocation/re-enrollment.

## LATER

- determine final credential serialization/authentication integration after security review;
- code signing;
- production installer/uninstaller;
- structured telemetry/audit logs without secrets;
- independent security review and threat-model review;
- release engineering.

## NOT A GOAL YET

Production deployment. Recovery paths and native Windows providers remain mandatory throughout development.
