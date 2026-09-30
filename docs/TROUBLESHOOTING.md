# PhoneKey troubleshooting

For the full BLE incident history, sanitized timing evidence, driver-update procedure, and regression-test method, see [BLE-TRANSPORT-TROUBLESHOOTING.md](BLE-TRANSPORT-TROUBLESHOOTING.md).

This guide is for the enrolled Windows laptop and Android pilot. Keep the normal Windows PIN/password available at all times. Do not delete PhoneKey protected state, uninstall the Android app, or overwrite trust files as a first response to a stall.

## QR accepted on phone, but no fingerprint prompt

The phone does not show biometrics merely because a QR was scanned. It waits for the matching live BLE challenge from Windows.

Capture Android timing logs:

```powershell
$adb = "$env:USERPROFILE\AndroidTools\platform-tools\adb.exe"
& $adb logcat -c
& $adb logcat -s PhoneKeyTiming:I '*:S'
```

Interpret the stages:

- `ble_advertising_ready` with no `ble_client_connected`: Windows has not connected to the phone. Check/reset Windows Bluetooth first.
- `ble_client_connected` with no `ble_challenge_received`: Windows found the phone, but GATT challenge delivery is failing.
- `biometric_queued` but no `biometric_launch`: return PhoneKey to the foreground and give it window focus.
- `biometric_launch` followed by `biometric_succeeded`: the phone approved the request; investigate proof delivery or Windows verification if sign-in still stalls.

## Windows stays at "Scanning for PhoneKey..."

This means Windows is not seeing the PhoneKey BLE advertisement even though Android may report that it is advertising.

### Fastest known recovery on the pilot laptop

The most reliable recovery observed on the pilot laptop is a reversible restart of the Bluetooth adapter. Run PowerShell as Administrator from the repository root. Use a per-process execution-policy bypass rather than changing the machine-wide policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\windows\Reset-PhoneKeyBluetoothAdapter.ps1"

Get-Item ".\windows\phonekey-bluetooth-adapter-result.txt" |
    Select-Object LastWriteTime

Get-Content ".\windows\phonekey-bluetooth-adapter-result.txt"
```

Check `LastWriteTime` before trusting the result file; an older successful result can remain on disk if a later script invocation was blocked or never ran.

Expected result:

```text
OK: Realtek Bluetooth Adapter restarted and healthy.
```

Then reopen the normal PhoneKey app, tap **Developer: Start BLE**, and retry with a fresh QR.

A lighter Bluetooth-service restart can be tried first:

```powershell
.\windows\Restart-PhoneKeyBluetooth.ps1
Get-Content ".\windows\phonekey-bluetooth-restart-result.txt"
```

If discovery still fails, restart the Bluetooth adapter:

```powershell
.\windows\Reset-PhoneKeyBluetoothAdapter.ps1
Get-Content ".\windows\phonekey-bluetooth-adapter-result.txt"
```

If the service restart does not restore discovery, use the adapter-reset command above.

### Current root-cause assessment

The repeated stall pattern is strongly localized to the Windows/Realtek Bluetooth LE transport path, not Android biometrics. Evidence shows that the instability is not limited to advertisement discovery:

- Android reports `ble_advertising_ready`.
- During some stalls, Windows remains at `Scanning for PhoneKey...` and Android never logs `ble_client_connected`.
- In an earlier diagnostic, the Windows BLE probe saw zero advertisements from any device while Android was actively advertising.
- A Windows `BTHUSB` adapter-command timeout occurred near earlier failures.
- At least one captured Windows sign-in reached `4106` (phone found) and `4107` (challenge delivered) before `4191` (Bluetooth transport failed), proving that failures can also occur after discovery/connection.
- Restarting only the Bluetooth service did not always recover scanning.
- Disabling/re-enabling the Realtek Bluetooth adapter repeatedly restored advertisement discovery during earlier stalls.
- After the OEM Bluetooth-driver update and restart, the first captured end-to-end PhoneKey test completed successfully; repeated testing is still required before calling that a permanent fix.

The best current description is intermittent instability in the Windows/Realtek BLE transport path, sometimes affecting discovery/connection and sometimes the GATT/proof exchange after connection. This does **not** prove which internal Realtek/Windows/WinRT component is defective.

To narrow it further without changing PhoneKey code, capture the adapter and driver details after a stall:

```powershell
Get-PnpDevice -PresentOnly -Class Bluetooth |
    Select-Object Status,FriendlyName,InstanceId

Get-CimInstance Win32_PnPSignedDriver |
    Where-Object { $_.DeviceName -match 'Realtek.*Bluetooth' } |
    Select-Object DeviceName,DriverVersion,DriverDate,Manufacturer,InfName

Get-WinEvent -FilterHashtable @{
    LogName='System'
    StartTime=(Get-Date).AddMinutes(-15)
} |
Where-Object {
    $_.ProviderName -match 'BTHUSB|BTHMINI|Bluetooth'
} |
Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message
```

Microsoft also recommends updating the Bluetooth driver, checking Windows Update, and installing the latest laptop-manufacturer Bluetooth/firmware updates for recurring detection failures.

## Fingerprint succeeds, but Windows still does not unlock

Return with the normal Windows PIN and collect the privacy-safe Windows sign-in timeline:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\windows\Get-PhoneKeySignInDiagnostics.ps1"
```

Important stages:

- `4105` — Bluetooth discovery started.
- `4106` — Phone advertisement found; connecting.
- `4107` — BLE challenge delivered; waiting for phone approval.
- `4108` — Phone proof received; verifying.
- `4191` — Bluetooth transport failed.
- `4194` — challenge expired.

Do not remove the Credential Provider or protected trust state just because one sign-in stalls.

## If the Android app was uninstalled, reset, or its app data was cleared

Android uninstall removes the app's private data and normally destroys its non-exportable Android Keystore identity. Reinstalling the APK does not recreate the old key. Windows must trust a newly enrolled phone identity.

Use the normal `PhoneKey-Android-Preview.apk`, not the side-by-side test package, for the real enrollment.

Safe recovery sequence:

1. Sign into Windows with the normal PIN/password.
2. Reinstall and open the normal PhoneKey app.
3. Grant Bluetooth permissions and start BLE advertising.
4. Preserve any existing trust/account-binding rollback state. Do not delete protected-state files merely to make a script continue.
5. Start or renew the protected Windows enrollment challenge.
6. Run the Windows broker with `enroll` so the challenge is actually transported over BLE.
7. Approve the enrollment biometric prompt on Android.
8. Compare the six-digit code shown on Android with the code returned by the protected Windows helper.
9. Confirm only if the two codes are identical.
10. Rebind the existing Windows account binding to the newly verified phone identity.
11. Verify `PhoneKeyService` is Running/Automatic and test one real lock-screen sign-in while the normal PIN remains available.

The Windows broker step is required. `PAIRING_READY` or `PAIRING_RENEWED` only creates the LocalSystem enrollment challenge; it does not send that challenge to Android.

Typical broker command:

```powershell
& $broker enroll
```

A healthy enrollment transport progresses through:

```text
Scanning for PhoneKey...
PHONEKEY FOUND
Connecting to PhoneKey...
Connected.
Sending the exact LocalSystem EnrollmentChallenge...
LocalSystem challenge delivered unchanged.
```

If the broker stays at `Scanning for PhoneKey...`, fix BLE discovery before touching trust state.

## Protected-state safety

If a pairing helper reports that a previous protected trust backup already exists, stop and inspect the state before moving or deleting anything.

The active account binding must correspond to the active or parked trust being recovered. Never confirm a pairing code mismatch. Never delete `trusted_phone.json`, `authorized_account.json`, password vaults, or rollback copies simply to force the repair forward.

Use the normal Windows PIN/password until recovery is complete.

## Other checks

### Missing VC++ runtime DLLs
If the Credential Provider DLL fails to load, verify the x64 VC++ runtime and install the supported Microsoft VC++ x64 redistributable matching the build toolchain.

### Credential Provider not registered
Verify the exact CLSID/registration assets from the current source and use the version-controlled registration script. Never guess registry values.

### Service not running or wrong account

```powershell
Get-CimInstance Win32_Service -Filter "Name='PhoneKeyService'" |
    Select-Object Name,State,StartMode,StartName
```

The pilot expects the service to be Running, Automatic, and LocalSystem.

## Incident note — 29 Sep 2026

A real recovery on the pilot laptop reproduced a QR/enrollment stall where Android was advertising but Windows stayed at `Scanning for PhoneKey...`. Restarting the Realtek Bluetooth adapter with `Reset-PhoneKeyBluetoothAdapter.ps1` restored discovery. The broker then found the phone, connected, delivered the exact 96-byte LocalSystem enrollment challenge, received a 176-byte signed EnrollmentProof, and LocalSystem verified it. The pairing codes matched, enrollment was confirmed, the Windows account binding was rebound, and PhoneKey sign-in worked again.

The earlier no-fingerprint symptom was therefore not a biometric failure: Windows had not delivered a valid BLE challenge to Android.
