#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$resultPath = Join-Path $PSScriptRoot 'phonekey-bluetooth-restart-result.txt'
try {
    Restart-Service -Name bthserv -Force
    (Get-Service -Name bthserv).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    'OK: Windows Bluetooth service restarted and is running.' |
        Set-Content -LiteralPath $resultPath
} catch {
    "FAILED: $($_.Exception.Message)" | Set-Content -LiteralPath $resultPath
    throw
}
