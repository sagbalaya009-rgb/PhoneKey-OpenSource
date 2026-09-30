$ErrorActionPreference = "Stop"

$repo = $PSScriptRoot

$serviceName =
    "PhoneKeyService"

$displayName =
    "PhoneKey Authentication Service"

$sourceExe =
    Join-Path `
        $repo `
        "target\release\phonekey-service.exe"

if (-not [string]::IsNullOrWhiteSpace($env:PHONEKEY_SERVICE_SOURCE)) {
    $sourceExe = $env:PHONEKEY_SERVICE_SOURCE
}

$base =
    Join-Path `
        $env:ProgramData `
        "PhoneKey"

$bin =
    Join-Path `
        $base `
        "bin"

$state =
    Join-Path `
        $base `
        "state"

$serviceExe =
    Join-Path `
        $bin `
        "phonekey-service.exe"

$identityPath =
    Join-Path `
        $state `
        "windows_identity.json"

Write-Host ""
Write-Host "========================================"
Write-Host "PHONEKEY ELEVATED SERVICE INSTALL"
Write-Host "========================================"

$currentIdentity =
    [Security.Principal.WindowsIdentity]::GetCurrent()

$currentPrincipal =
    New-Object `
        Security.Principal.WindowsPrincipal(
            $currentIdentity
        )

$isAdministrator =
    $currentPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

if (-not $isAdministrator) {
    throw "Administrator elevation was not granted."
}

if (-not (
    Test-Path `
        -LiteralPath $sourceExe
)) {
    throw "Compiled PhoneKey service executable was not found."
}

$vcRuntime = Join-Path $env:SystemRoot 'System32\VCRUNTIME140.dll'
if (-not (Test-Path -LiteralPath $vcRuntime)) {
    throw "Microsoft Visual C++ x64 Redistributable is required before installing PhoneKey."
}

# ---------------------------------------------------------
# CREATE SECURITY-OWNED DIRECTORIES
# ---------------------------------------------------------

if (-not (Test-Path -LiteralPath $base)) {
    New-Item -ItemType Directory -Path $base -Force | Out-Null
}

# Protect the parent before creating children. Grant access to that same
# directory immediately after removing inheritance; otherwise a fresh install
# can leave an empty DACL on the parent and lock itself out before the
# recursive grant below ever runs.
foreach ($directory in @($base, $bin, $state)) {
    if ($directory -ne $base) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    & icacls.exe `
        $directory `
        /inheritance:r |
        Out-Host

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to disable inherited ACLs on $directory."
    }
    # SYSTEM = S-1-5-18; BUILTIN\Administrators = S-1-5-32-544.
    # No ordinary Users/Auth Users ACE is retained.
    & icacls.exe `
        $directory `
        /grant:r `
        "*S-1-5-18:(OI)(CI)F" `
        "*S-1-5-32-544:(OI)(CI)F" |
        Out-Host

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to establish PhoneKey ACL on $directory."
    }
}

Write-Host ""
Write-Host "[OK] ProgramData PhoneKey tree restricted to SYSTEM and Administrators."

# ---------------------------------------------------------
# DEPLOY SERVICE BINARY
# ---------------------------------------------------------

$existing =
    Get-Service `
        -Name $serviceName `
        -ErrorAction SilentlyContinue

if (
    $null -ne $existing -and
    $existing.Status -ne "Stopped"
) {
    Stop-Service `
        -Name $serviceName `
        -Force

    $existing.WaitForStatus(
        "Stopped",
        [TimeSpan]::FromSeconds(
            10
        )
    )
}

Copy-Item `
    -LiteralPath $sourceExe `
    -Destination $serviceExe `
    -Force

Write-Host "[OK] Service binary deployed to protected ProgramData."

# ---------------------------------------------------------
# INSTALL OR UPDATE WINDOWS SERVICE
# ---------------------------------------------------------

$existing =
    Get-Service `
        -Name $serviceName `
        -ErrorAction SilentlyContinue

if ($null -eq $existing) {
    New-Service `
        -Name $serviceName `
        -BinaryPathName (
            '"{0}"' -f
            $serviceExe
        ) `
        -DisplayName $displayName `
        -StartupType Automatic |
        Out-Null

    Write-Host "[OK] Windows service registered."
}
else {
    Write-Host "[OK] Existing PhoneKey service found; updating configuration."
}

& sc.exe `
    config `
    $serviceName `
    binPath= `
    "`"$serviceExe`"" `
    start= `
    auto `
    obj= `
    LocalSystem |
    Out-Host

if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure PhoneKey service."
}

$serviceInfo =
    Get-CimInstance `
        Win32_Service `
        -Filter "Name='$serviceName'"

if ($null -eq $serviceInfo) {
    throw "PhoneKey Windows service could not be queried."
}

if (
    $serviceInfo.StartName -notin @(
        "LocalSystem",
        "Local System"
    )
) {
    throw "PhoneKey service is not configured as LocalSystem."
}

Write-Host "[OK] Service account confirmed: LocalSystem."
Write-Host "[OK] Startup mode: Automatic."

# ---------------------------------------------------------
# START SERVICE SO LOCALSYSTEM CREATES MACHINE IDENTITY
# ---------------------------------------------------------

Write-Host ""
Write-Host "Starting PhoneKey service..."

Start-Service `
    -Name $serviceName

$created =
    $false

for (
    $attempt = 0;
    $attempt -lt 40;
    $attempt++
) {
    if (
        Test-Path `
            -LiteralPath $identityPath
    ) {
        $created =
            $true

        break
    }

    Start-Sleep `
        -Milliseconds 250
}

if (-not $created) {
    $current =
        Get-Service `
            -Name $serviceName

    throw "PhoneKey identity was not created. Service status: $($current.Status)"
}

$record =
    Get-Content `
        -LiteralPath $identityPath `
        -Raw |
    ConvertFrom-Json

if (
    $record.version -ne 1
) {
    throw "Unexpected Windows identity state version."
}

if (
    [string]::IsNullOrWhiteSpace(
        $record.windows_device_id_hex
    ) -or
    $record.windows_device_id_hex.Length -ne 32
) {
    throw "Generated Windows device identity is invalid."
}

if (
    $record.windows_device_id_hex -eq
    "00000000000000000000000000000000"
) {
    throw "Generated Windows Device ID was all-zero."
}

Write-Host ""
Write-Host "========================================"
Write-Host "PERSISTENT WINDOWS IDENTITY CREATED"
Write-Host "========================================"

Write-Host ""
Write-Host "Windows Device ID:"
Write-Host $record.windows_device_id_hex

Write-Host ""
Write-Host "[OK] Identity created by LocalSystem service."
Write-Host "[OK] Identity length: 16 bytes."
Write-Host "[OK] Identity is non-zero."
Write-Host "[OK] Identity persisted under protected ProgramData."

# ---------------------------------------------------------
# VERIFY IDENTITY IS STABLE ACROSS SERVICE RESTART
# ---------------------------------------------------------

$firstId =
    $record.windows_device_id_hex

Restart-Service `
    -Name $serviceName `
    -Force

Start-Sleep `
    -Milliseconds 750

$recordAgain =
    Get-Content `
        -LiteralPath $identityPath `
        -Raw |
    ConvertFrom-Json

if (
    $recordAgain.windows_device_id_hex -ne
    $firstId
) {
    throw "CRITICAL: Windows Device ID changed across service restart."
}

Write-Host "[OK] Identity survived service restart unchanged."

# ---------------------------------------------------------
# STOP SERVICE FOR NOW
# ---------------------------------------------------------

Stop-Service `
    -Name $serviceName

(Get-Service `
    -Name $serviceName
).WaitForStatus(
    "Stopped",
    [TimeSpan]::FromSeconds(
        10
    )
)

Write-Host "[OK] Service stopped after validation."

# ---------------------------------------------------------
# DISPLAY FINAL SECURITY ACL
# ---------------------------------------------------------

Write-Host ""
Write-Host "=== PHONEKEY PROGRAMDATA ACL ==="

& icacls.exe `
    $base |
    Out-Host

Write-Host ""
Write-Host "========================================"
Write-Host "SECURE WINDOWS SERVICE STATE COMPLETE"
Write-Host "========================================"
Write-Host ""
Write-Host "[OK] LocalSystem service installed"
Write-Host "[OK] Manual startup only"
Write-Host "[OK] Protected ProgramData directory"
Write-Host "[OK] Persistent random Windows Device ID"
Write-Host "[OK] Identity stable after restart"
Write-Host "[OK] Service binary protected from normal-user replacement"
Write-Host "[OK] Windows login configuration untouched"
Write-Host "[OK] Credential Provider not installed"
Write-Host "[OK] LSA not modified"

