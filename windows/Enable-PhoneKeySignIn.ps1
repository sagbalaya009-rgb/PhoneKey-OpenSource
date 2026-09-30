#Requires -RunAsAdministrator
# Restore the installed PhoneKey tile after checking the normal Windows fallback.
$ErrorActionPreference = 'Stop'
$providerRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$phoneKey = Join-Path $providerRoot '{D32C6E35-E46E-43DC-8175-7DF63A1AC293}'
$nativePassword = @(Get-ChildItem -LiteralPath $providerRoot | Where-Object {
    (Get-Item -LiteralPath $_.PSPath).GetValue('') -eq 'PasswordProvider'
})
if ($nativePassword.Count -lt 1) { throw 'Native Windows password sign-in is unavailable; refusing to change sign-in tiles.' }
if ((Get-Service PhoneKeyService -ErrorAction Stop).Status -ne 'Running') {
    throw 'PhoneKey service must be running before enabling its sign-in tile.'
}
if (-not (Test-Path -LiteralPath 'C:\ProgramData\PhoneKey\state\password_vault.bin') -and
    -not (Test-Path -LiteralPath 'C:\ProgramData\PhoneKey\state\password_vault_local.bin')) {
    throw 'Both PhoneKey account password vaults are missing.'
}
$dll = 'C:\Program Files\PhoneKey\CredentialProvider\PhoneKeyCredentialProvider.dll'
if (-not (Test-Path -LiteralPath $dll)) { throw 'Installed PhoneKey sign-in component is missing.' }
if (Test-Path -LiteralPath $phoneKey) {
    Write-Output 'PhoneKey sign-in is already enabled.'
    return
}

try {
    & reg.exe import (Join-Path $PSScriptRoot 'credential-provider\register.reg') | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $phoneKey)) {
        throw 'Could not register the PhoneKey sign-in tile.'
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PhoneKeyEnableComProbe {
    [DllImport("ole32.dll", PreserveSig = true)]
    public static extern int CoCreateInstance(ref Guid classId, IntPtr outer,
        uint context, ref Guid interfaceId, out IntPtr instance);
}
'@
    $classId = [Guid]'D32C6E35-E46E-43DC-8175-7DF63A1AC293'
    $interfaceId = [Guid]'00000000-0000-0000-C000-000000000046'
    $instance = [IntPtr]::Zero
    $result = [PhoneKeyEnableComProbe]::CoCreateInstance(
        [ref]$classId,[IntPtr]::Zero,1,[ref]$interfaceId,[ref]$instance)
    if ($instance -ne [IntPtr]::Zero) { [void][Runtime.InteropServices.Marshal]::Release($instance) }
    if ($result -ne 0) { throw ('PhoneKey sign-in component could not load: 0x{0:X8}' -f ($result -band 0xffffffffL)) }
    Write-Output 'PhoneKey sign-in enabled. Normal Windows sign-in remains available.'
} catch {
    & reg.exe import (Join-Path $PSScriptRoot 'credential-provider\Unregister.reg') | Out-Null
    throw
}
