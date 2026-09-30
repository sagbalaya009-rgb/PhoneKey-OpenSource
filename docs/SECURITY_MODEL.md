# Security Model

PhoneKey changes the Windows authentication surface. Treat every component and deployment step as security-sensitive.

## Trust boundaries

- **Android private key:** intended to be non-exportable and user-auth gated.
- **BLE:** hostile/untrusted transport.
- **LocalSystem service:** intended authoritative PhoneKey policy/state boundary.
- **IPC:** privileged local boundary; normal-user processes must not gain privileged commands.
- **Credential Provider:** exposed to LogonUI/secure-desktop constraints; intentionally thin.
- **Persistent state:** must be machine-protected, versioned and tamper-aware in the reconciled implementation.

## Threats and required properties

- **Replay/stale challenges:** single-use sessions, nonces, expiry and atomic consumption.
- **Wrong account:** cryptographically/policy-bind proof to explicit Windows SID/account.
- **Wrong machine:** stable machine identity must be included in the trust relationship.
- **Malicious local user process:** cannot impersonate the privileged service or invoke privileged IPC operations.
- **Compromised/revoked phone:** revocation must prevent future authorization; phone compromise remains a major trust failure and requires recovery/revocation.
- **BLE interception/spoofing:** BLE pairing alone is insufficient; application-layer proof is required.
- **State tampering/rollback:** protected-state integrity/version/migration behavior must be verified from recovered source; the Aug-27 SQLite baseline is not proof of the later design.
- **Downgrade:** protocol/version negotiation must reject unsafe versions rather than silently downgrade.
- **CP attack surface:** minimal parsing/state/crypto; authoritative decisions remain in service.
- **Secrets:** no Windows password, biometric template, phone private key, real pairing secret or machine protected-state database in source control.

## Recovery invariant

Native Windows password/PIN/Hello recovery must remain available during development. CP registration/unregistration and service rollback must be tested in a disposable VM before lock-screen testing.

## Security review status

No professional security review is claimed. September hardening work is historically evidenced but its source is not currently preserved in GitHub. Until reconciled, do not describe the missing implementation as secure, complete or production-ready.
