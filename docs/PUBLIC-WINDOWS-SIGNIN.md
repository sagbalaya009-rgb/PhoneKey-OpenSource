# Public Windows sign-in release gate

PhoneKey's source is public and open source. This document describes the separate gate for calling the **Windows sign-in feature a general consumer release**.

## Current pilot behavior

A real pilot has completed QR scan, phone biometric approval, signed proof verification, and automatic Windows unlock on one enrolled Windows 11 laptop and one Android phone, including post-restart testing.

The current pilot uses a LocalSystem service and a native Credential Provider. For the tested Microsoft-account compatibility path, the Windows machine can keep a locally protected encrypted Windows credential and release it once only after a verified PhoneKey transaction. The credential does not travel to the phone.

Native Windows PIN/password providers remain available.

This is a local compatibility implementation. It is **not** a general passwordless Windows architecture.

## Current observability

The Windows path records privacy-safe stage IDs such as:

- `4100` — QR/session created;
- `4105` — BLE discovery started;
- `4106` — PhoneKey advertisement found;
- `4107` — challenge delivered;
- `4108` — proof received/verification started;
- `4101` — proof accepted;
- `4102` — credential redemption started;
- `4103` — credential handed to Windows;
- `4104` — Windows accepted the credential;
- `4191` — BLE transport failure;
- `4194` — challenge expired.

These diagnostics intentionally avoid account names, SIDs, QR contents, keys, passwords, and proof bytes.

## Account support

| Account type | Current project status | General-release gate |
|---|---|---|
| Microsoft account | Tested on the enrolled pilot laptop using the local protected compatibility bridge | Define/verify a supported public architecture, then test recovery, multi-PC behavior, password/account changes and failure reporting |
| Local Windows account | Source contains separate local-account handling; broad live compatibility is not established | Test enrollment, unlock, account transitions and recovery across several PCs |
| Active Directory / Microsoft Entra ID | Not supported | Separate policy, authentication, enrollment, domain/join and managed-environment testing |

## Why a phone signature is not automatically a Windows logon

The Credential Provider gathers/presents credential material, but the Windows authentication stack makes the final sign-in decision.

A PhoneKey signature proves the enrolled phone approved the session. It does not by itself become a Microsoft-account workstation credential.

Any production design must use a Windows-supported authentication path for the account type being advertised.

## Release criteria

Before PhoneKey should be presented as a general public Windows sign-in product:

1. Define the supported Windows authentication route for every advertised account type.
2. Keep PhoneKey's signed phone approval cryptographically bound to a fresh, one-use Windows transaction.
3. Test cancellation, expiry, BLE loss, changed credentials, account mismatch, service crash, reboot, Windows Update, uninstall and rollback.
4. Validate on multiple Windows machines, Bluetooth adapters and Android devices.
5. Provide a production installer/uninstaller and stable code signing.
6. Keep native Windows recovery available and test recovery before release.
7. Complete an independent security review of the service/IPC/Credential Provider boundaries and secret handling.
8. Document the supported device/account matrix and known limitations.

The public repository can be useful for review, testing and contribution before these product-release gates are complete.
