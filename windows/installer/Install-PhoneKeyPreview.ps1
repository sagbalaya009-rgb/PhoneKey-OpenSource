[CmdletBinding()]
param([switch]$PreflightOnly)

$ErrorActionPreference = 'Stop'
$serviceName = 'PhoneKeyService'
$classId = '{D32C6E35-E46E-43DC-8175-7DF63A1AC293}'
$providerRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$providerKey = Join-Path $providerRoot $classId
$comKey = "HKLM:\SOFTWARE\Classes\CLSID\$classId"
$marker = 'HKLM:\SOFTWARE\PhoneKey\PreviewInstaller'
$programRoot = Join-Path $env:ProgramFiles 'PhoneKey'
$providerDirectory = Join-Path $programRoot 'CredentialProvider'
$setupDirectory = Join-Path $programRoot 'Setup'
$stateRoot = Join-Path $env:ProgramData 'PhoneKey'
$serviceDirectory = Join-Path $stateRoot 'bin'
$stateDirectory = Join-Path $stateRoot 'state'
$serviceTarget = Join-Path $serviceDirectory 'phonekey-service.exe'
$providerTarget = Join-Path $providerDirectory 'PhoneKeyCredentialProvider.dll'
$payload = @{
    'phonekey-service.exe' = Join-Path $PSScriptRoot 'phonekey-service.exe'
    'broker.exe' = Join-Path $PSScriptRoot 'broker.exe'
    'PhoneKeyCredentialProvider.dll' = Join-Path $PSScriptRoot 'PhoneKeyCredentialProvider.dll'
    'Complete-PhoneKeyPreview.ps1' = Join-Path $PSScriptRoot 'Complete-PhoneKeyPreview.ps1'
    'Uninstall-PhoneKeyPreview.ps1' = Join-Path $PSScriptRoot 'Uninstall-PhoneKeyPreview.ps1'
    'Set-PhoneKeyPassword.ps1' = Join-Path $PSScriptRoot 'Set-PhoneKeyPassword.ps1'
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-PreviewPrerequisites {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'PhoneKey preview requires 64-bit Windows.'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    if ([int]$os.BuildNumber -lt 22000 -or $os.ProductType -ne 1) {
        throw 'This preview supports Windows 11 client only.'
    }
    $account = Get-LocalUser -SID ([Security.Principal.WindowsIdentity]::GetCurrent().User) -ErrorAction Stop
    if ($account.PrincipalSource -ne 'Local') {
        throw 'This preview installer currently supports local Windows accounts only. The existing Microsoft-account laptop pilot is unchanged.'
    }
    $nativePassword = @(Get-ChildItem -LiteralPath $providerRoot -ErrorAction Stop | Where-Object {
        (Get-Item -LiteralPath $_.PSPath).GetValue('') -eq 'PasswordProvider'
    })
    if ($nativePassword.Count -eq 0) { throw 'Native Windows password sign-in must remain available.' }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw 'A PhoneKey service already exists. This installer never upgrades or replaces an existing sign-in.'
    }
    foreach ($path in @($providerKey, $comKey, $marker, $programRoot, $stateRoot)) {
        if (Test-Path -LiteralPath $path) { throw "Existing PhoneKey installation/state detected: $path" }
    }
    foreach ($entry in $payload.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "Installer payload is missing: $($entry.Key)"
        }
    }
    $manifestPath = Join-Path $PSScriptRoot 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Installer checksum manifest is missing.' }
    $expected = @{}
    foreach ($line in Get-Content -LiteralPath $manifestPath) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9.-]+)$') { throw 'Invalid installer checksum manifest.' }
        $expected[$Matches[2]] = $Matches[1]
    }
    if ($expected.Count -ne $payload.Count) { throw 'Installer checksum manifest has the wrong file count.' }
    foreach ($entry in $payload.GetEnumerator()) {
        $hash = (Get-FileHash -LiteralPath $entry.Value -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expected[$entry.Key] -ne $hash) { throw "Installer file failed checksum verification: $($entry.Key)" }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\VCRUNTIME140.dll'))) {
        throw 'Microsoft Visual C++ x64 runtime is required for the Credential Provider.'
    }
}

Assert-PreviewPrerequisites
if ($PreflightOnly) {
    Write-Output 'PhoneKey preview preflight passed. No changes were made.'
    return
}
if (-not (Test-Administrator)) {
    $quoted = '"' + $PSCommandPath.Replace('"', '""') + '"'
    $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $quoted" -PassThru -Wait
    exit $child.ExitCode
}

$serviceCreated = $false
try {
    New-Item -ItemType Directory -Path $providerDirectory, $setupDirectory, $serviceDirectory, $stateDirectory -Force | Out-Null
    foreach ($directory in @($stateRoot, $serviceDirectory, $stateDirectory)) {
        & icacls.exe $directory /inheritance:r | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not remove inherited access from $directory" }
        & icacls.exe $directory /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not protect $directory" }
    }
    Copy-Item -LiteralPath $payload['phonekey-service.exe'] -Destination $serviceTarget
    Copy-Item -LiteralPath $payload['PhoneKeyCredentialProvider.dll'] -Destination $providerTarget
    foreach ($name in @('broker.exe', 'Complete-PhoneKeyPreview.ps1', 'Uninstall-PhoneKeyPreview.ps1', 'Set-PhoneKeyPassword.ps1')) {
        Copy-Item -LiteralPath $payload[$name] -Destination (Join-Path $setupDirectory $name)
    }
    foreach ($pair in @(@($payload['phonekey-service.exe'], $serviceTarget), @($payload['PhoneKeyCredentialProvider.dll'], $providerTarget))) {
        if ((Get-FileHash -LiteralPath $pair[0]).Hash -ne (Get-FileHash -LiteralPath $pair[1]).Hash) {
            throw 'Installed binary failed verification.'
        }
    }
    New-Service -Name $serviceName -BinaryPathName ('"{0}"' -f $serviceTarget) -DisplayName 'PhoneKey Authentication Service' -StartupType Automatic | Out-Null
    $serviceCreated = $true
    $configuration = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $configuration -or $configuration.StartName -notin @('LocalSystem', 'Local System')) {
        throw 'PhoneKey service is not running under LocalSystem.'
    }
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    $identityPath = Join-Path $stateDirectory 'windows_identity.json'
    for ($attempt = 0; $attempt -lt 40 -and -not (Test-Path -LiteralPath $identityPath); $attempt++) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $identityPath)) { throw 'PhoneKey service did not create its protected identity.' }
    $identityRecord = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    if ($identityRecord.version -ne 1 -or $identityRecord.windows_device_id_hex -notmatch '^[0-9a-f]{32}$') {
        throw 'PhoneKey service identity is invalid.'
    }
    New-Item -Path $marker -Force | Out-Null
    New-ItemProperty -Path $marker -Name 'Version' -Value 'preview-1' -PropertyType String -Force | Out-Null
    Write-Output 'PhoneKey files and service installed; the sign-in tile is still disabled.'
    Write-Output "To pair a phone and enable the tile, run $setupDirectory\Complete-PhoneKeyPreview.ps1 as this local account."
    Write-Output "To remove this preview, run $setupDirectory\Uninstall-PhoneKeyPreview.ps1."
} catch {
    $failure = $_.Exception.Message
    if ($serviceCreated) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
    }
    foreach ($path in @($programRoot, $stateRoot)) {
        $expectedPath = if ($path -eq $programRoot) { Join-Path $env:ProgramFiles 'PhoneKey' } else { Join-Path $env:ProgramData 'PhoneKey' }
        if ([IO.Path]::GetFullPath($path).TrimEnd('\') -ne [IO.Path]::GetFullPath($expectedPath).TrimEnd('\')) {
            throw "Setup rollback refused unexpected path: $path. Original failure: $failure"
        }
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw "PhoneKey setup failed without enabling its sign-in tile: $failure"
}
