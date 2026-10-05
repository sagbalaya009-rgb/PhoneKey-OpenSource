[CmdletBinding()]
param([switch]$KeepState, [switch]$PreflightOnly)

$ErrorActionPreference = 'Stop'
$marker = 'HKLM:\SOFTWARE\PhoneKey\PreviewInstaller'
$classId = '{D32C6E35-E46E-43DC-8175-7DF63A1AC293}'
$providerRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$providerKey = Join-Path $providerRoot $classId
$classKey = "HKLM:\SOFTWARE\Classes\CLSID\$classId"
$programRoot = Join-Path $env:ProgramFiles 'PhoneKey'
$stateRoot = Join-Path $env:ProgramData 'PhoneKey'

if (-not (Test-Path -LiteralPath $marker)) {
    throw 'This PC was not installed by the PhoneKey preview installer. Refusing to remove an existing PhoneKey setup.'
}
$record = Get-ItemProperty -LiteralPath $marker -ErrorAction Stop
if ($record.Version -ne 'preview-1') { throw 'Unknown PhoneKey installer version. Refusing uninstall.' }
$nativePassword = @(Get-ChildItem -LiteralPath $providerRoot -ErrorAction Stop | Where-Object {
    (Get-Item -LiteralPath $_.PSPath).GetValue('') -eq 'PasswordProvider'
})
if ($nativePassword.Count -eq 0) { throw 'Native Windows password sign-in is unavailable. Refusing uninstall.' }
if ($PreflightOnly) {
    Write-Output 'PhoneKey preview uninstall preflight passed. No changes were made.'
    return
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run uninstall from an elevated PowerShell window.'
}

# Remove only the PhoneKey tile first. Native Windows sign-in is never edited.
Remove-Item -LiteralPath $providerKey -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $providerKey) { throw 'Could not remove the PhoneKey sign-in tile.' }
Remove-Item -LiteralPath $classKey -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $classKey) { throw 'Could not remove the PhoneKey COM registration.' }

$service = Get-Service PhoneKeyService -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name PhoneKeyService -Force
        (Get-Service PhoneKeyService).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    & sc.exe delete PhoneKeyService | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not unregister PhoneKeyService. The sign-in tile is disabled.' }
}

function Remove-ExactDirectory {
    param([string]$Target, [string]$Expected)
    $actualFull = [IO.Path]::GetFullPath($Target).TrimEnd('\')
    $expectedFull = [IO.Path]::GetFullPath($Expected).TrimEnd('\')
    if (-not [string]::Equals($actualFull, $expectedFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unexpected cleanup target: $Target"
    }
    if (Test-Path -LiteralPath $Target) {
        Remove-Item -LiteralPath $Target -Recurse -Force -ErrorAction Stop
    }
}

Remove-ExactDirectory -Target $programRoot -Expected (Join-Path $env:ProgramFiles 'PhoneKey')
if (-not $KeepState) {
    Remove-ExactDirectory -Target $stateRoot -Expected (Join-Path $env:ProgramData 'PhoneKey')
}
Remove-Item -LiteralPath $marker -Force
Write-Output 'PhoneKey preview removed. Native Windows sign-in remains available.'
if ($KeepState) { Write-Output "Protected PhoneKey pairing/vault state was retained at $stateRoot." }
