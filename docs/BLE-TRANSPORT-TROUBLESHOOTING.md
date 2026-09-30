# PhoneKey BLE transport troubleshooting and pilot incident record

This document records the BLE failures observed during the PhoneKey Windows 11 ↔ Android pilot, the evidence used to localize them, the recovery steps that worked, and the diagnostic procedure to use if the problem returns.

It is intentionally evidence-driven. A successful recovery does not prove a single vendor component was at fault. Keep the normal Windows PIN/password available while testing.

## Executive summary

The recurring PhoneKey stall was not an Android biometric problem.

Observed failures occurred in the Windows/Realtek Bluetooth LE transport path and appeared in more than one place:

- in some attempts, Android reached `ble_advertising_ready` but Windows never connected;
- in some attempts, Windows reached discovery/connection stages but the GATT/proof exchange later failed;
- Windows event stage `4191` was observed after `4107` on at least one attempt, proving the failure was not limited to advertisement discovery;
- restarting the Realtek Bluetooth adapter repeatedly restored PhoneKey discovery during the earlier stalls;
- after updating the OEM Bluetooth driver and rebooting, the first captured PhoneKey sign-in completed the full BLE + biometric path successfully.

The best current description is therefore:

> intermittent instability in the Windows/Realtek BLE transport path, sometimes affecting discovery/connection and sometimes the GATT/proof exchange after connection.

This does **not** prove whether the defect is inside the Realtek driver/radio, the Windows Bluetooth stack, WinRT BLE discovery/GATT behavior, or their interaction.

## Pilot environment

The affected pilot machine is an ASUS TUF Gaming A15 FA506NCQ running Windows 11. The Bluetooth adapter is a Realtek device.

An earlier captured Bluetooth driver state was:

```text
DeviceName    : Realtek Bluetooth Adapter
DriverVersion : 18.4032.2509.1900
DriverDate    : 09/19/25
Manufacturer  : Realtek Semiconductor Corp.
InfName       : oem42.inf
```

Do not assume that version is still installed. Always query the current machine before drawing conclusions:

```powershell
Get-CimInstance Win32_PnPSignedDriver |
    Where-Object { $_.DeviceName -match 'Realtek.*Bluetooth' } |
    Select-Object DeviceName,DriverVersion,DriverDate,Manufacturer,InfName
```

The pilot was later updated using the current ASUS-provided Bluetooth package for the laptop, followed by a Windows restart. Because only a limited number of post-update PhoneKey runs had been completed when this incident was documented, the driver update should be treated as a promising mitigation rather than a proven permanent fix.

## Symptom pattern

The common user-visible sequence was:

1. PhoneKey Android app starts BLE advertising.
2. Windows PhoneKey presents a QR.
3. The phone accepts/scans the QR.
4. The phone can remain on `PhoneKey is advertising over BLE`.
5. No fingerprint prompt appears because a matching live Windows BLE challenge has not reached the Android app.
6. Resetting the Realtek Bluetooth adapter often makes the next attempt work.

Important: scanning the QR is not itself authentication. PhoneKey still requires the fresh matching BLE challenge and phone biometric approval.

## Android timing logger

Use ADB to capture the PhoneKey timing tags:

```powershell
$adb = "$env:USERPROFILE\AndroidTools\platform-tools\adb.exe"

& $adb logcat -c
& $adb logcat -s PhoneKeyTiming:I '*:S'
```

Clear the log **once before the test**, then leave it running. Do not clear it again after a stall or the useful failure sequence will be erased.

If `adb devices` shows no device, recover ADB before diagnosing PhoneKey:

```powershell
$adb = "$env:USERPROFILE\AndroidTools\platform-tools\adb.exe"

& $adb kill-server
& $adb start-server
& $adb devices
```

A healthy USB-debugging connection should show the phone with status `device`. If it shows `unauthorized`, approve the USB-debugging prompt on the phone.

### Timing-stage interpretation

- `ble_advertise_requested` — Android requested BLE advertising.
- `ble_advertising_ready` — Android reports that the advertiser is active.
- `ble_client_connected` — a Windows BLE client connected.
- `ble_challenge_received` — Windows delivered the PhoneKey login challenge over GATT.
- `challenge_arrived_before_qr` — valid race condition; PhoneKey defers the challenge until the matching QR is accepted.
- `biometric_queued` — the matched login request is ready for user verification.
- `biometric_launch` — Android biometric UI launched.
- `biometric_succeeded` — local user approval succeeded.
- `proof_ready_to_ble_read_ms=...` — signed proof is ready for Windows to read.
- `ble_client_disconnected` — Windows disconnected from the GATT server.

Useful failure boundaries:

- `ble_advertising_ready` but no `ble_client_connected`: investigate Windows discovery/radio/driver state.
- `ble_client_connected` but no `ble_challenge_received`: investigate GATT challenge delivery.
- biometric succeeds but Windows does not unlock: investigate proof transport and Windows verification stages.

## Successful post-driver-update trace — 30 Sep 2026

The first captured sign-in after the driver update/restart produced:

```text
09-30 19:35:55.498 PhoneKeyTiming: ble_advertise_requested
09-30 19:35:55.571 PhoneKeyTiming: ble_advertising_ready
09-30 19:36:13.292 PhoneKeyTiming: ble_advertise_requested
09-30 19:36:13.822 PhoneKeyTiming: ble_advertising_ready
09-30 19:36:14.585 PhoneKeyTiming: ble_client_connected
09-30 19:36:15.093 PhoneKeyTiming: ble_challenge_received
09-30 19:36:15.099 PhoneKeyTiming: challenge_arrived_before_qr
09-30 19:36:16.749 PhoneKeyTiming: biometric_queued kind=LOGIN resumed=false focus=false
09-30 19:36:16.807 PhoneKeyTiming: activity_resumed
09-30 19:36:16.955 PhoneKeyTiming: activity_focused
09-30 19:36:16.956 PhoneKeyTiming: scan_to_prompt_ms=207
09-30 19:36:16.956 PhoneKeyTiming: biometric_launch kind=LOGIN
09-30 19:36:21.095 PhoneKeyTiming: biometric_succeeded
09-30 19:36:21.161 PhoneKeyTiming: prompt_to_proof_ms=4205
09-30 19:36:21.232 PhoneKeyTiming: activity_focused
09-30 19:36:21.289 PhoneKeyTiming: proof_ready_to_ble_read_ms=129
09-30 19:36:24.534 PhoneKeyTiming: ble_client_disconnected
```

This is a healthy end-to-end Android/BLE trace. In particular, Windows connected, delivered the challenge, Android launched biometrics, generated the proof, and the BLE client disconnected normally.

Do not treat one successful run as proof that the Bluetooth-driver change permanently solved the intermittent failure. Repeat multiple lock-screen sign-ins without resetting the adapter between attempts.

## Windows sign-in stage diagnostics

Run the repository diagnostic script after returning to Windows with the normal PIN/password:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\windows\Get-PhoneKeySignInDiagnostics.ps1"
```

Important event stages:

- `4100` — QR challenge created.
- `4105` — Bluetooth discovery started.
- `4106` — Phone advertisement found; connecting.
- `4107` — BLE challenge delivered; waiting for phone approval.
- `4108` — Phone proof received; verifying.
- `4191` — Bluetooth transport failed.
- `4194` — Phone challenge expired.
- `4101` — phone proof accepted.
- `4102` — credential redemption started.
- `4103` — credential handed to Windows.
- `4104` — Windows accepted the credential.

One captured failure reached `4106` and `4107` and then produced `4191`. That is why the incident should not be described as a discovery-only problem.

## Safe recovery when Windows scanning stalls

Do **not** uninstall the Android app, delete protected state, delete trust/account-binding files, or re-enroll the phone for an ordinary BLE stall.

Try the lighter Bluetooth service recovery first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\windows\Restart-PhoneKeyBluetooth.ps1"
```

If discovery still fails, restart the Bluetooth adapter:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\windows\Reset-PhoneKeyBluetoothAdapter.ps1"
```

Run the recovery command from the repository root. The `-ExecutionPolicy Bypass` option applies only to that PowerShell process. Do not weaken the machine-wide execution policy just to run a PhoneKey recovery script.

### Avoid stale result files

A previous result file can remain on disk even when a later script invocation was blocked or never ran. Check its timestamp before trusting its contents:

```powershell
Get-Item ".\windows\phonekey-bluetooth-adapter-result.txt" |
    Select-Object LastWriteTime
```

Then inspect it:

```powershell
Get-Content ".\windows\phonekey-bluetooth-adapter-result.txt"
```

Expected successful adapter recovery:

```text
OK: Realtek Bluetooth Adapter restarted and healthy.
```

After recovery, reopen the normal PhoneKey Android app, tap **Developer: Start BLE**, wait for advertising to become ready, and use a fresh Windows QR.

## Driver update procedure

For recurring Bluetooth discovery/transport failures:

1. Prefer the laptop manufacturer's current Bluetooth package for the exact model.
2. Install only the newer applicable package; do not install both old and new revisions.
3. Let the installer replace/update the active driver. Do not manually delete the old driver first unless the OEM procedure explicitly requires it.
4. Restart Windows after the Bluetooth driver update.
5. Query the installed driver version.
6. Test PhoneKey repeatedly **without** resetting Bluetooth first. Otherwise the reset itself contaminates the test.
7. If a stall occurs, capture Android and Windows diagnostics before resetting the adapter.

Driver updates can improve stability, compatibility, latency, power management, and bug behavior, but they do not increase the hardware's fundamental capabilities.

## Windows Bluetooth evidence to collect after a stall

Before resetting Bluetooth, capture:

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

Earlier investigation also found a BTHUSB adapter-command timeout near a prior failure. That is useful supporting evidence, but it does not independently identify the precise faulty layer.

## Regression test after a Bluetooth change

For a meaningful validation:

1. restart Windows after the Bluetooth-driver change;
2. do not pre-emptively reset the Bluetooth adapter;
3. start Android timing logs once and leave them running;
4. open the normal PhoneKey app and start BLE;
5. perform a normal lock-screen QR + biometric sign-in;
6. repeat at least 10 times if practical;
7. record any first failure before attempting recovery;
8. if all repeated attempts succeed, describe the result as strong evidence of improvement, not absolute proof.

## Safety boundaries

For a normal BLE stall, do not:

- uninstall the PhoneKey Android app;
- clear PhoneKey app data;
- delete `trusted_phone.json`, `authorized_account.json`, encrypted password vaults, protected-state files, or rollback copies;
- repeatedly re-enroll the phone;
- weaken machine-wide PowerShell execution policy;
- remove the native Windows PIN/password fallback.

Re-enrollment is appropriate only when the Android identity genuinely changed, such as after uninstall/reset/app-data loss, not as a routine response to transport instability.
