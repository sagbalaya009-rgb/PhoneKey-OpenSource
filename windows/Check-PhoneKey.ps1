# Read-only health check for the one-laptop PhoneKey installation.
# Run from PowerShell; no administrator prompt or phone password is required.
param([switch]$CheckVault)
$ErrorActionPreference = 'Stop'
$issues = [System.Collections.Generic.List[string]]::new()
$serviceName = 'PhoneKeyService'
$classId = '{D32C6E35-E46E-43DC-8175-7DF63A1AC293}'
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$classId"
$comKey = "HKLM:\SOFTWARE\Classes\CLSID\$classId\InprocServer32"

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
    $issues.Add('PhoneKey service is not installed.')
} else {
    if ($service.Status -ne 'Running') { $issues.Add('PhoneKey service is not running.') }
    if ($service.StartType -ne 'Automatic') { $issues.Add('PhoneKey service is not set to start automatically.') }
}

$configuration = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction SilentlyContinue
if ($null -eq $configuration -or $configuration.ObjectName -ne 'LocalSystem') {
    $issues.Add('PhoneKey service is not configured for LocalSystem.')
}

if (-not (Test-Path -LiteralPath $providerKey)) {
    $issues.Add('PhoneKey sign-in tile is not registered.')
}
$com = Get-Item -LiteralPath $comKey -ErrorAction SilentlyContinue
$providerPath = if ($com) { [string]$com.GetValue('') } else { '' }
if ([string]::IsNullOrWhiteSpace($providerPath) -or
    -not (Test-Path -LiteralPath $providerPath)) {
    $issues.Add('PhoneKey sign-in component is missing.')
}

$nativeProviders = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$passwordProvider = @(Get-ChildItem -LiteralPath $nativeProviders -ErrorAction SilentlyContinue |
    Where-Object { (Get-Item -LiteralPath $_.PSPath).GetValue('') -eq 'PasswordProvider' })
if ($passwordProvider.Count -lt 1) {
    $issues.Add('Native Windows password sign-in is not registered.')
}

# The pilot keeps separate encrypted vaults for local and Microsoft sign-in.
# A change of Windows account type requires enrolling that type's password.
try {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $account = Get-LocalUser -SID $sid -ErrorAction Stop
    if ($account.PrincipalSource -notin @('Local', 'MicrosoftAccount')) {
        $issues.Add('This Windows account type is not supported by the PhoneKey pilot.')
    } elseif ($CheckVault) {
        $vaultName = if ($account.PrincipalSource -eq 'Local') { 'password_vault_local.bin' } else { 'password_vault.bin' }
        $vaultPath = Join-Path 'C:\ProgramData\PhoneKey\state' $vaultName
        if (-not (Test-Path -LiteralPath $vaultPath)) {
            $issues.Add("The $($account.PrincipalSource) password vault is missing or inaccessible. Enroll the matching password from elevated PowerShell before using PhoneKey.")
        }
    }
} catch {
    $issues.Add('Could not verify this Windows profile account type.')
}

if ($issues.Count -eq 0) {
    Write-Output 'PhoneKey health: Core OK. Service running automatically; sign-in tile and native Windows fallback registered. Password correctness requires a real sign-in test.'
    exit 0
}
foreach ($issue in $issues) { Write-Output "PhoneKey health: $issue" }
Write-Output 'Use the normal Windows PIN or password until PhoneKey is repaired.'
exit 1
