#Requires -RunAsAdministrator
# Reversible device restart for a radio whose LE watcher receives no packets.
$ErrorActionPreference = 'Stop'
$resultPath = Join-Path $PSScriptRoot 'phonekey-bluetooth-adapter-result.txt'
$adapter = @(Get-PnpDevice -PresentOnly -Class Bluetooth |
    Where-Object { $_.FriendlyName -eq 'Realtek Bluetooth Adapter' -and $_.Status -eq 'OK' })
if ($adapter.Count -ne 1) { throw 'Expected one healthy Realtek Bluetooth Adapter; no device changed.' }
$instanceId = $adapter[0].InstanceId
$disabled = $false
try {
    Disable-PnpDevice -InstanceId $instanceId -Confirm:$false
    $disabled = $true
    Start-Sleep -Seconds 3
    Enable-PnpDevice -InstanceId $instanceId -Confirm:$false
    $disabled = $false
    Start-Sleep -Seconds 4
    $after = Get-PnpDevice -InstanceId $instanceId
    if ($after.Status -ne 'OK') { throw "Bluetooth adapter status after restart: $($after.Status)" }
    'OK: Realtek Bluetooth Adapter restarted and healthy.' |
        Set-Content -LiteralPath $resultPath
} catch {
    $failure = $_.Exception.Message
    if ($disabled) {
        try { Enable-PnpDevice -InstanceId $instanceId -Confirm:$false } catch {
            $failure += "; enable failed: $($_.Exception.Message)"
        }
    }
    "FAILED: $failure" | Set-Content -LiteralPath $resultPath
    throw
}
