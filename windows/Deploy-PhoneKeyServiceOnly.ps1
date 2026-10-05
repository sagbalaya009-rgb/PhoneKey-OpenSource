#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $SourcePath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedSha256
)
$ErrorActionPreference = 'Stop'
$serviceName = 'PhoneKeyService'
$source = if ($SourcePath) { $SourcePath } else { Join-Path $PSScriptRoot 'target\release\phonekey-service.exe' }
$target = 'C:\ProgramData\PhoneKey\bin\phonekey-service.exe'
$result = Join-Path $env:TEMP 'PhoneKey.ServiceDeploy.Result.txt'
$backup = "$target.$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')).bak"
$stopped = $false
$replaced = $false
try {
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $service -or $service.StartName -notin @('LocalSystem', 'Local System') -or
        $service.PathName.Trim('"') -ne $target) {
        throw 'Unexpected PhoneKey service configuration.'
    }
    if (-not (Test-Path -LiteralPath $source) -or -not (Test-Path -LiteralPath $target)) {
        throw 'PhoneKey service executable missing.'
    }
    if ($ExpectedSha256 -and (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ine $ExpectedSha256) {
        throw 'Source service does not match the verified build hash.'
    }
    Copy-Item -LiteralPath $target -Destination $backup
    if ((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $backup).Hash) {
        throw 'Backup verification failed.'
    }
    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    $stopped = $true
    Copy-Item -LiteralPath $source -Destination $target -Force
    $replaced = $true
    if ((Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath $target).Hash) {
        throw 'Installed service hash mismatch.'
    }
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    'SERVICE_DEPLOYED' | Set-Content -LiteralPath $result
} catch {
    $cause = $_.Exception.Message
    try {
        if ($replaced) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
            Copy-Item -LiteralPath $backup -Destination $target -Force
        }
        if ($stopped) { Start-Service -Name $serviceName }
        "ROLLED_BACK: $cause" | Set-Content -LiteralPath $result
    } catch {
        "ROLLBACK_NEEDS_ATTENTION: $cause; $($_.Exception.Message)" | Set-Content -LiteralPath $result
    }
    throw
}
