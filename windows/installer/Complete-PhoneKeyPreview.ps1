[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$state = Join-Path $env:ProgramData 'PhoneKey\state'
$trust = Join-Path $state 'trusted_phone.json'
$binding = Join-Path $state 'authorized_account.json'
$vault = Join-Path $state 'password_vault_local.bin'
$courier = Join-Path $env:TEMP 'PhoneKey.ServiceEnrollmentChallenge.v1.bin'
$marker = 'HKLM:\SOFTWARE\PhoneKey\PreviewInstaller'
$classId = '{D32C6E35-E46E-43DC-8175-7DF63A1AC293}'
$providerRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$providerKey = Join-Path $providerRoot $classId
$classKey = "HKLM:\SOFTWARE\Classes\CLSID\$classId"
$dll = Join-Path $env:ProgramFiles 'PhoneKey\CredentialProvider\PhoneKeyCredentialProvider.dll'
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$account = Get-LocalUser -SID ([Security.Principal.WindowsIdentity]::GetCurrent().User) -ErrorAction Stop
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run setup from an elevated PowerShell window under the local account that will use PhoneKey.'
}
if ($account.PrincipalSource -ne 'Local') { throw 'This preview supports local Windows accounts only.' }
if (-not (Test-Path -LiteralPath $marker)) { throw 'The PhoneKey preview installer marker is missing. Refusing to modify this PC.' }
if ((Get-Service PhoneKeyService -ErrorAction Stop).Status -ne 'Running') { throw 'PhoneKeyService is not running.' }
if (-not (Test-Path -LiteralPath $dll)) { throw 'PhoneKey Credential Provider DLL is missing.' }

function Invoke-PhoneKeyControl {
    param([byte]$Command, [byte[]]$Payload = @())
    [byte[]]$frame = New-Object byte[] (12 + $Payload.Length)
    $frame[0] = 0x50; $frame[1] = 0x4b; $frame[2] = 0x49; $frame[3] = 0x32
    $frame[4] = 2; $frame[5] = $Command
    $length = [uint32]$Payload.Length
    for ($index = 0; $index -lt 4; $index++) {
        $frame[8 + $index] = [byte](($length -shr (24 - $index * 8)) -band 0xff)
    }
    if ($Payload.Length) { [Array]::Copy($Payload, 0, $frame, 12, $Payload.Length) }
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'PhoneKey.Control.v2',
        [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(5000)
        $pipe.ReadMode = [IO.Pipes.PipeTransmissionMode]::Message
        $pipe.Write($frame, 0, $frame.Length)
        $pipe.Flush()
        $memory = [IO.MemoryStream]::new()
        try {
            [byte[]]$buffer = New-Object byte[] 4096
            do {
                $read = $pipe.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { throw 'PhoneKeyService closed its response early.' }
                $memory.Write($buffer, 0, $read)
            } while (-not $pipe.IsMessageComplete)
            [byte[]]$response = $memory.ToArray()
        } finally { $memory.Dispose() }
        if ($response.Length -lt 12 -or $response[0] -ne 0x50 -or $response[1] -ne 0x4b -or
            $response[2] -ne 0x52 -or $response[3] -ne 0x32 -or $response[4] -ne 2 -or
            $response[6] -ne 0 -or $response[7] -ne 0) {
            throw 'Invalid PhoneKeyService response.'
        }
        $size = [uint32]0
        for ($index = 0; $index -lt 4; $index++) { $size = ($size -shl 8) -bor [uint32]$response[8 + $index] }
        if ($response.Length -ne 12 + $size) { throw 'PhoneKeyService response length mismatch.' }
        if ($response[5] -ne 0) { throw "PhoneKeyService refused command $Command (status $($response[5]))." }
        if ($size -eq 0) { return ,([byte[]]@()) }
        return ,([byte[]]$response[12..($response.Length - 1)])
    } finally {
        [Array]::Clear($frame, 0, $frame.Length)
        $pipe.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $trust)) {
    $pending = $false
    try {
        [byte[]]$challenge = Invoke-PhoneKeyControl -Command 2
        if ($challenge.Length -ne 96) { throw 'Unexpected enrollment challenge size.' }
        $pending = $true
        [IO.File]::WriteAllBytes($courier, $challenge)
        Write-Output 'Open PhoneKey on Android and start Bluetooth advertising. Approve its enrollment prompt.'
        & (Join-Path $PSScriptRoot 'broker.exe') enroll
        if ($LASTEXITCODE -ne 0) { throw 'Bluetooth enrollment broker failed.' }
        [byte[]]$codeBytes = Invoke-PhoneKeyControl -Command 10
        if ($codeBytes.Length -ne 4) { throw 'Invalid pairing code from service.' }
        $number = [uint32]0
        foreach ($octet in $codeBytes) { $number = ($number -shl 8) -bor [uint32]$octet }
        if ($number -ge 1000000) { throw 'Pairing code is out of range.' }
        $code = '{0:D6}' -f $number
        Write-Output "Windows pairing code: $code"
        $typed = Read-Host 'Type the six-digit code shown on your phone only if it matches Windows'
        if ($typed -cne $code) { throw 'Pairing codes did not match. No phone trust was saved.' }
        [void](Invoke-PhoneKeyControl -Command 4 -Payload $codeBytes)
        $pending = $false
        if (-not (Test-Path -LiteralPath $trust)) { throw 'Phone trust was not saved.' }
    } finally {
        Remove-Item -LiteralPath $courier -Force -ErrorAction SilentlyContinue
        if ($pending) { try { [void](Invoke-PhoneKeyControl -Command 5) } catch {} }
    }
}
if (-not (Test-Path -LiteralPath $binding)) { [void](Invoke-PhoneKeyControl -Command 9) }
$bound = Get-Content -LiteralPath $binding -Raw | ConvertFrom-Json
if ($bound.windows_sid -ne $currentSid) { throw 'PhoneKey is bound to a different Windows account.' }
if (-not (Test-Path -LiteralPath $vault)) {
    & (Join-Path $PSScriptRoot 'Set-PhoneKeyPassword.ps1') -AccountType Local
    if (-not (Test-Path -LiteralPath $vault)) { throw 'Local password vault was not created.' }
}
if (Test-Path -LiteralPath $providerKey) {
    Write-Output 'PhoneKey sign-in tile is already enabled. Keep your normal Windows password/PIN available.'
    return
}
$nativePassword = @(Get-ChildItem -LiteralPath $providerRoot | Where-Object {
    (Get-Item -LiteralPath $_.PSPath).GetValue('') -eq 'PasswordProvider'
})
if ($nativePassword.Count -eq 0) { throw 'Native Windows password sign-in is unavailable. Refusing to enable PhoneKey.' }
try {
    New-Item -Path $classKey -Force | Out-Null
    Set-Item -Path $classKey -Value 'PhoneKey Credential Provider'
    $inproc = Join-Path $classKey 'InprocServer32'
    New-Item -Path $inproc -Force | Out-Null
    Set-Item -Path $inproc -Value $dll
    New-ItemProperty -Path $inproc -Name ThreadingModel -Value Apartment -PropertyType String -Force | Out-Null
    New-Item -Path $providerKey -Force | Out-Null
    Set-Item -Path $providerKey -Value 'PhoneKey Credential Provider'
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PhoneKeyPreviewComProbe {
    [DllImport("ole32.dll", PreserveSig = true)]
    public static extern int CoCreateInstance(ref Guid classId, IntPtr outer,
        uint context, ref Guid interfaceId, out IntPtr instance);
}
'@
    $classGuid = [Guid]'D32C6E35-E46E-43DC-8175-7DF63A1AC293'
    $interfaceGuid = [Guid]'00000000-0000-0000-C000-000000000046'
    $instance = [IntPtr]::Zero
    $result = [PhoneKeyPreviewComProbe]::CoCreateInstance([ref]$classGuid,
        [IntPtr]::Zero, 1, [ref]$interfaceGuid, [ref]$instance)
    if ($instance -ne [IntPtr]::Zero) { [void][Runtime.InteropServices.Marshal]::Release($instance) }
    if ($result -ne 0) { throw ('Credential Provider cannot load: 0x{0:X8}' -f ($result -band 0xffffffffL)) }
    Write-Output 'PhoneKey sign-in enabled. Test it with your normal Windows password/PIN available.'
} catch {
    Remove-Item -LiteralPath $providerKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $classKey -Recurse -Force -ErrorAction SilentlyContinue
    throw
}
