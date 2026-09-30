# Repository Guide

| Path | Purpose |
|---|---|
| `windows/Cargo.toml` | Recovered Rust workspace |
| `windows/protocol/` | Protocol, crypto, session, proof and enrollment primitives/tests |
| `windows/service/` | Authoritative LocalSystem Windows service |
| `windows/broker/` | Recovered broker/admin utilities retained from Stage-E |
| `windows/credential-provider/` | Native Credential Provider + IPC transport + transport tests |
| `android/` | Recovered Android Studio companion project |
| `docs/` | Current architecture/security/build/test/deployment documentation |
| `recovery/archives/` | Exact recovered source/history/artifact archives and checksums |
| `.github/workflows/` | CI and recovery/reconstruction provenance |
| `SOURCE_OF_TRUTH.md` | Canonical-source declaration |
| `legacy-source-note.md` | Where the older August layout went |

## Start here

1. `README.md`
2. `SOURCE_OF_TRUTH.md`
3. `docs/CURRENT_STATE.md`
4. `docs/ARCHITECTURE.md`
5. `docs/SECURITY_MODEL.md`
6. `docs/BUILD.md`
7. `docs/TESTING.md`

## History

The August implementation remains available in Git history and the preservation branch. The active tree on the recovery branch is the recovered September implementation.

Do not copy older August files back into the active tree merely because their paths differ. Reconcile behavior intentionally.
