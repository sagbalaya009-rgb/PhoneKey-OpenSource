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
    4090 = 'PhoneKey tile selected'
    4091 = 'PhoneKey tile deselected; approval cleared'
    4092 = 'Verified transaction retained on tile reselection'
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
    4200 = 'BLE watcher started'
    4201 = 'BLE advertisement selected; opening device'
    4202 = 'BLE device opened; querying service'
    4203 = 'BLE service acquired; querying characteristics'
    4204 = 'BLE characteristics acquired; writing challenge'
    4205 = 'BLE challenge acknowledged; polling proof'
    4206 = 'BLE proof received'
    4290 = 'BLE watcher aborted'
    4291 = 'BLE service query failed'
    4292 = 'BLE characteristic query failed'
    4293 = 'BLE challenge write failed'
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
            $stage = if ($event.ProviderName -in @('PhoneKey Sign-In', 'PhoneKey BLE') -and
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
