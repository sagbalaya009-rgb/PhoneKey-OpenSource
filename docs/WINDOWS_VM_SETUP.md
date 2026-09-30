# Windows VM Setup

Use a disposable Windows 11 x64 VM for all Credential Provider/service registration work.

## Safety first

1. Keep native password/PIN/Hello enabled.
2. Create a VM snapshot before service or CP registration.
3. Confirm an administrator recovery account.
4. Prepare unregistration/rollback commands before Win+L.
5. Never test first on the primary machine.

## Preflight (PowerShell as Administrator)

```powershell
[Environment]::Is64BitOperatingSystem
Get-Command sc.exe
Get-Command reg.exe
Get-Item "$env:WINDIR\System32\VCRUNTIME140.dll" -ErrorAction SilentlyContinue
Get-Item "$env:WINDIR\System32\VCRUNTIME140_1.dll" -ErrorAction SilentlyContinue
Get-Item "$env:WINDIR\System32\MSVCP140.dll" -ErrorAction SilentlyContinue
```

Validate artifact hashes before copying/installing:
```powershell
Get-FileHash .\phonekey-service.exe -Algorithm SHA256
Get-FileHash .\PhoneKeyCredentialProvider.dll -Algorithm SHA256
```

## Service verification

After using the **reconciled project's** installer script/known service command:
```powershell
Get-CimInstance Win32_Service -Filter "Name='PhoneKeyService'" |
  Select-Object Name, State, StartMode, StartName
```

Historical later-state expectation was `Running / Auto / LocalSystem`. Verify rather than assume.

## Credential Provider

Use only the registration/unregistration scripts recovered with the exact CP source/build. Do not invent CLSIDs or registry paths from memory. Confirm DLL x64 architecture and dependencies before registration.

## Logs and diagnosis

Use service-specific logs if present and Windows Event Viewer for service/LogonUI failures. Capture timestamps and hashes, but never commit credentials, pairing secrets, raw protected state or private keys.

## Lock-screen test gate

Do not press Win+L until:
- snapshot exists;
- native providers are confirmed;
- CP unregistration is known and tested;
- service can be stopped/removed;
- artifact architecture/dependencies are verified;
- the exact source/commit for the DLL is known.
