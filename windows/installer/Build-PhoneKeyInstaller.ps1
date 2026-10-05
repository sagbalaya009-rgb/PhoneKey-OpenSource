[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$windowsRoot = Split-Path -Parent $PSScriptRoot
$repository = Split-Path -Parent $windowsRoot
$stage = Join-Path $windowsRoot 'target\preview-installer'
$target = Join-Path $repository 'dist\PhoneKey-Windows-Setup-Preview.exe'
$inputs = [ordered]@{
    'phonekey-service.exe' = Join-Path $windowsRoot 'target\release\phonekey-service.exe'
    'broker.exe' = Join-Path $windowsRoot 'target\release\broker.exe'
    'PhoneKeyCredentialProvider.dll' = Join-Path $windowsRoot 'credential-provider\x64\Release\SampleV2CredentialProvider.dll'
    'Install-PhoneKeyPreview.ps1' = Join-Path $PSScriptRoot 'Install-PhoneKeyPreview.ps1'
    'Complete-PhoneKeyPreview.ps1' = Join-Path $PSScriptRoot 'Complete-PhoneKeyPreview.ps1'
    'Uninstall-PhoneKeyPreview.ps1' = Join-Path $PSScriptRoot 'Uninstall-PhoneKeyPreview.ps1'
    'Set-PhoneKeyPassword.ps1' = Join-Path $windowsRoot 'Set-PhoneKeyPassword.ps1'
}
foreach ($entry in $inputs.GetEnumerator()) {
    if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
        throw "Missing installer build input: $($entry.Value)"
    }
}
New-Item -ItemType Directory -Path $stage, (Split-Path -Parent $target) -Force | Out-Null
foreach ($entry in $inputs.GetEnumerator()) {
    Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $stage $entry.Key) -Force
}
$manifest = foreach ($entry in $inputs.GetEnumerator()) {
    if ($entry.Key -eq 'Install-PhoneKeyPreview.ps1') { continue }
    '{0}  {1}' -f (Get-FileHash -LiteralPath (Join-Path $stage $entry.Key) -Algorithm SHA256).Hash.ToLowerInvariant(), $entry.Key
}
Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Value $manifest -Encoding ASCII
$payload = Join-Path $stage 'payload.zip'
if (Test-Path -LiteralPath $payload) { Remove-Item -LiteralPath $payload -Force }
$names = @($inputs.Keys) + 'SHA256SUMS.txt'
Compress-Archive -LiteralPath @($names | ForEach-Object { Join-Path $stage $_ }) -DestinationPath $payload

$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw 'The .NET Framework C# compiler is unavailable.' }
$source = Join-Path $PSScriptRoot 'PhoneKeySetup.cs'
$outputArgument = '/out:{0}' -f $target
$resourceArgument = '/resource:{0},PhoneKey.Payload' -f $payload
& $csc /nologo /target:exe /platform:x64 /optimize+ $outputArgument $resourceArgument `
    /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll $source
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target -PathType Leaf)) {
    throw 'PhoneKey setup EXE did not compile.'
}
Write-Output $target
Write-Output ('SHA256=' + (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash)
