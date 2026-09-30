#Requires -RunAsAdministrator
# Emergency fallback: hide only the PhoneKey tile. Keep native Windows sign-in and all PhoneKey state.
$ErrorActionPreference = 'Stop'
$providerRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$phoneKey = Join-Path $providerRoot '{D32C6E35-E46E-43DC-8175-7DF63A1AC293}'
$nativePassword = @(Get-ChildItem -LiteralPath $providerRoot | Where-Object {
    (Get-Item -LiteralPath $_.PSPath).GetValue('') -eq 'PasswordProvider'
})
if ($nativePassword.Count -lt 1) { throw 'Native Windows password sign-in is unavailable; refusing to change sign-in tiles.' }
if (-not (Test-Path -LiteralPath $phoneKey)) {
    Write-Output 'PhoneKey sign-in is already disabled. Use the normal Windows PIN or password.'
    return
}
& reg.exe import (Join-Path $PSScriptRoot 'credential-provider\Unregister.reg') | Out-Null
if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $phoneKey)) {
    throw 'Could not disable the PhoneKey sign-in tile.'
}
Write-Output 'PhoneKey sign-in disabled. The service and enrolled phone were left intact; use the normal Windows PIN or password.'
