# Read-only timeline around an attempted PhoneKey sign-in. No secrets or
# account names are collected. Run in PowerShell after returning with a PIN.
[CmdletBinding()]
param(
    [datetime] $At = (Get-Date),
    [ValidateRange(1, 60)] [int] $MinutesBefore = 5,
    [ValidateRange(1, 60)] [int] $MinutesAfter = 2
)

$ErrorActionPreference = 'Stop'
$start = $At.AddMinutes(-$MinutesBefore)
$end = $At.AddMinutes($MinutesAfter)
$stages = @{
    4100 = 'QR challenge created'
    4101 = 'Phone proof accepted'
    4102 = 'Credential redemption started'
    4103 = 'Credential handed to Windows'
    4104 = 'Windows accepted credential'
    4105 = 'Bluetooth discovery started'
    4106 = 'Phone advertisement found; connecting'
    4107 = 'BLE challenge delivered; waiting for phone approval'
    4108 = 'Phone proof received; verifying'
    4190 = 'Credential redemption failed'
    4191 = 'Bluetooth transport failed'
    4192 = 'Windows rejected submitted credential'
    4193 = 'Windows rejected saved account password; refresh required'
    4194 = 'Phone challenge expired'
}
$service = Get-Service -Name 'PhoneKeyService' -ErrorAction SilentlyContinue
[pscustomobject]@{
    Check = 'Service'
    At = (Get-Date).ToString('o')
    Result = if ($service) { "$($service.Status) / $($service.StartType)" } else { 'Missing' }
}

foreach ($log in @('Microsoft-Windows-Winlogon/Operational', 'Application', 'System')) {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $log
            StartTime = $start
            EndTime = $end
        } -ErrorAction Stop
        foreach ($event in $events) {
            if ($log -ne 'Microsoft-Windows-Winlogon/Operational' -and
                $event.Level -notin @(1, 2, 3) -and
                $event.ProviderName -notmatch 'PhoneKey|Service Control Manager|Application Error|Windows Error Reporting') {
                continue
            }
            # Provider, event ID and time are enough to locate a failure. Do
            # not print event Message: it may contain an account or path.
            $stage = if ($event.ProviderName -eq 'PhoneKey Sign-In' -and
                $stages.ContainsKey([int]$event.Id)) {
                " Stage=$($stages[[int]$event.Id])"
            } else { '' }
            [pscustomobject]@{
                Check = $log
                At = $event.TimeCreated.ToString('o')
                Result = "ID=$($event.Id) Level=$($event.LevelDisplayName) Provider=$($event.ProviderName)$stage"
            }
        }
    } catch {
        [pscustomobject]@{
            Check = $log
            At = ''
            Result = 'No readable events in the selected time window'
        }
    }
}
