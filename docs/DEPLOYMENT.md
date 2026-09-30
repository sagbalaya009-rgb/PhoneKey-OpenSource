# Deployment and Recovery

Deployment is VM-first and recovery-first.

## Staging contract

Every deployment bundle should identify:
- source commit;
- target architecture;
- service executable;
- Credential Provider DLL;
- registration/unregistration assets;
- manifest;
- SHA-256 for each binary;
- build date/environment;
- known limitations.

Historical bundles reportedly included `PhoneKeyCredentialProvider.dll`, `phonekey-service.exe`, registration/unregistration `.reg` files and `MANIFEST.txt`. Old hashes must never be reused for rebuilt binaries.

## Preflight

Verify x64 OS/artifacts, VC++ runtime dependencies, service identity requirements, native-provider recovery, hashes and rollback path. Do not register a CP merely because a DLL exists.

## Service

The intended later service account is LocalSystem. Verify with `Get-CimInstance Win32_Service`; do not rely on the service name/status alone.

## Credential Provider

Registration changes Windows logon behavior. Use only version-controlled, reviewed registration tooling tied to the exact CLSID/build. Preserve native Windows providers. Never disable fallback providers as part of PhoneKey testing.

## Rollback

Recovery must be possible without PhoneKey:
1. revert CP registration using the exact matching unregistration asset;
2. stop/remove the PhoneKey service if necessary;
3. restore the VM snapshot if LogonUI is unstable;
4. verify native password/PIN/Hello before further testing.

## Current limitation

The later September registration/deployment scripts and hashes are not present in the GitHub state audited on 20 Sep. Recover them from the surviving workspace/VM/archive before live deployment.
