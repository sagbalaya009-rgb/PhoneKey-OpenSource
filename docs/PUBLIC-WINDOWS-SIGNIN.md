# Public Windows sign-in release gate

## Current behavior

The installed pilot works for one enrolled TECNO and one Windows laptop. After a fresh QR and phone proof, the LocalSystem service releases that user's locally encrypted password for the current local or Microsoft account once to the Credential Provider, which submits it to Windows. Native Windows PIN/password providers remain available. The local-account route is newly installed but still needs a real local-account sign-in test. This is a local compatibility implementation, not general passwordless authentication.

The provider hides its tile for unsupported account types and independently refuses an unsupported selection before showing a QR. Serialization repeats the account check. If one-time password redemption fails, the provider returns a visible retry/PIN message. The release x64 DLL builds and 20 native IPC transport tests pass. The first-attempt stall reported on 24 Sep still needs a fresh real sign-in trace. The provider records privacy-safe event IDs for QR creation (4100), accepted phone proof (4101), redemption start (4102), handoff to Windows (4103), optional Windows acceptance callback (4104), redemption failure (4190), and Windows rejection (4192). It never logs account names, SIDs, QR contents, keys, passwords, or proof bytes. The updated DLL is installed and loaded successfully; a real sign-in test remains necessary.

## Account support decision

| Account type | Current pilot | Public release gate |
|---|---|---|
| Microsoft account | Works on the enrolled laptop with opt-in encrypted password storage | Held until a supported passwordless workstation-authentication route is verified; then test recovery, multi-PC behavior and account-failure reporting. |
| Local Windows account | Separate encrypted local vault and credential serialization installed; live sign-in not yet verified | Test enrollment, real unlock, account transitions, and recovery on several PCs before release. |
| Active Directory / Microsoft Entra ID | Not supported | Separate policy, authentication, enrollment and domain-join tests before offering the tile. |

The user selected **hold consumer Microsoft-account public support until a supported passwordless Windows route is verified**. The opt-in stored-password pilot must not be repackaged as the general consumer release. This decision does not remove the user's existing local pilot or its PIN fallback.

Windows' Credential Provider gathers and serializes credentials; the authentication package makes the final decision. A phone signature cannot by itself become a Microsoft-account Windows logon. The old Windows Hello Companion Device Framework is deprecated and must not be used as the public architecture. Microsoft's Web sign-in route targets Entra-joined devices, not all consumer Microsoft accounts. Windows passkey-provider plugins serve website/app passkeys and do not, by themselves, grant workstation logon. Relevant platform documentation: [Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows), [Companion Device Framework](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-companion-device-framework), [Web sign-in](https://learn.microsoft.com/en-us/windows/security/identity-protection/web-sign-in/), [Windows passkeys](https://learn.microsoft.com/en-us/windows/security/book/identity-protection-passwordless-sign-in).

## Exit criteria before moving to file encryption

1. Define and verify which Windows account types are supported, and how each authenticates without silently depending on another user's credential.
2. Make the sign-in flow observable: phone proof received, provider status, serialization attempted, Windows authentication result, and bounded retry. Log event codes and times only; never log passwords, QR content, keys or account identifiers.
3. Reproduce or capture enough evidence to classify the intermittent first-attempt stall, then verify the fix through lock/unlock and cold-boot trials. Keep native sign-in available throughout.
4. Test cancellation, expiry, lost Bluetooth, changed Microsoft password, account mismatch, service crash, and Windows update recovery.
5. Obtain independent security review of the Credential Provider, service boundary and secret handling before calling this a public sign-in feature.
