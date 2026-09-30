# Windows Platform Notes

These notes were checked against official Microsoft documentation on 27 August 2026.

## Credential Provider

`ICredentialProviderCredential` exposes the credential methods used by LogonUI, including field state/value access, selection, result reporting, bitmap retrieval, and `GetSerialization`. The provider serializes credential information for the underlying authentication engine; it is not the final authorization authority. PhoneKey therefore keeps authorization in the custom LSA package and returns zero credentials when disabled or unavailable.

The v1 provider targets `CPUS_LOGON` and `CPUS_UNLOCK_WORKSTATION`. The provider must preserve native providers and must not put a password into its serialized blob.

## LSA package

Windows loads registered SSP/AP DLLs into the LSA process at system startup and calls `SpLsaModeInitialize` to obtain security-package function tables. It then calls each package's `SpInitialize` with the LSA support function table. The PhoneKey LSA implementation must follow this registration and initialization contract and must remain fail-closed until its credential-buffer, session, trust, signature, and SID checks succeed.

## Official references

- [ICredentialProviderCredential](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nn-credentialprovider-icredentialprovidercredential)
- [GetSerialization](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredential-getserialization)
- [CREDENTIAL_PROVIDER_USAGE_SCENARIO](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/ne-credentialprovider-credential_provider_usage_scenario)
- [LSA Mode Initialization](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-mode-initialization)
- [Authentication Functions](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-functions)
