[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$output = Join-Path $repository 'dist\PhoneKey-Windows-Preview'
$inputs = [ordered]@{
    'phonekey-service.exe' = Join-Path $PSScriptRoot 'target\release\phonekey-service.exe'
    'broker.exe' = Join-Path $PSScriptRoot 'target\release\broker.exe'
    'PhoneKeyCredentialProvider.dll' = Join-Path $PSScriptRoot 'credential-provider\x64\Release\SampleV2CredentialProvider.dll'
}

foreach ($entry in $inputs.GetEnumerator()) {
    if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
        throw "Missing build output: $($entry.Value)"
    }
}

New-Item -ItemType Directory -Path $output -Force | Out-Null
foreach ($entry in $inputs.GetEnumerator()) {
    Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $output $entry.Key) -Force
}

$notice = @'
PhoneKey Windows developer preview

These are the built Windows components, not a one-click installer. Do not run
phonekey-service.exe by double-clicking it or register the Credential Provider
on a daily-use PC. The Windows service, provider DLL, protected state,
enrollment, account binding, recovery, and PIN/password fallback require a
separately tested installer. Public Microsoft-account sign-in is held until a
supported passwordless Windows route is verified.

This package contains no phone pairing, password vault, keys, or user data.
Source and current release gates are in the PhoneKey repository.
'@
Set-Content -LiteralPath (Join-Path $output 'README.txt') -Value $notice -Encoding UTF8

$manifest = foreach ($entry in $inputs.GetEnumerator()) {
    $file = Join-Path $output $entry.Key
    '{0}  {1}' -f (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant(), $entry.Key
}
Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Value $manifest -Encoding ASCII

$archive = Join-Path $repository 'dist\PhoneKey-Windows-Preview.zip'
Compress-Archive -LiteralPath $output -DestinationPath $archive -Force
Write-Output $archive
