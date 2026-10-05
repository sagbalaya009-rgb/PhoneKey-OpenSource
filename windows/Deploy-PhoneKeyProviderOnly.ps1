#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $SourcePath = (Join-Path $PSScriptRoot 'credential-provider\x64\Release\SampleV2CredentialProvider.dll'),
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedSha256
)
$ErrorActionPreference = 'Stop'
$source = $SourcePath
$target = 'C:\Program Files\PhoneKey\CredentialProvider\PhoneKeyCredentialProvider.dll'
$result = Join-Path $env:TEMP 'PhoneKey.ProviderDeploy.Result.txt'
$backup = "$target.$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')).bak"
try {
    $key = 'HKLM:\SOFTWARE\Classes\CLSID\{D32C6E35-E46E-43DC-8175-7DF63A1AC293}\InprocServer32'
    $registered = (Get-Item -LiteralPath $key).GetValue('')
    if ($registered -ne $target) { throw 'Unexpected PhoneKey credential provider registration.' }
    if (-not (Test-Path -LiteralPath $source) -or -not (Test-Path -LiteralPath $target)) {
        throw 'Credential provider binary missing.'
    }
    if ($ExpectedSha256 -and (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ine $ExpectedSha256) {
        throw 'Source provider does not match the verified build hash.'
    }
    Copy-Item -LiteralPath $target -Destination $backup
    if ((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $backup).Hash) {
        throw 'Backup verification failed.'
    }
    Copy-Item -LiteralPath $source -Destination $target -Force
    if ((Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath $target).Hash) {
        throw 'Installed provider hash mismatch.'
    }
    'PROVIDER_DEPLOYED' | Set-Content -LiteralPath $result
} catch {
    $cause = $_.Exception.Message
    try {
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $target -Force }
        "ROLLED_BACK: $cause" | Set-Content -LiteralPath $result
    } catch {
        "ROLLBACK_NEEDS_ATTENTION: $cause; $($_.Exception.Message)" | Set-Content -LiteralPath $result
    }
    throw
}
