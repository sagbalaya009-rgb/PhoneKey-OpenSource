param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Register', 'Encrypt', 'ViewText', 'OpenTo', 'RecoverTo')]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [string]$OutputPath,
    [switch]$TemporaryOpen
)

$ErrorActionPreference = 'Stop'
$buildDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target'))
$binary = Join-Path $buildDirectory 'release\phonekey-files.exe'
$result = Join-Path $buildDirectory 'file-vault-ui-result.txt'
$workDirectory = Join-Path $env:LOCALAPPDATA ('PhoneKey\file-vault\session\' + [guid]::NewGuid().ToString('N'))
$qrImage = Join-Path $workDirectory 'file-open-qr.bmp'
$expiryPath = [System.IO.Path]::ChangeExtension($qrImage, '.expiry')
$approvedMarker = Join-Path $workDirectory 'approved.txt'

try {
    if (!(Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw 'Build the separate PhoneKey Files application first.'
    }
    if ($Mode -in @('Encrypt', 'OpenTo', 'RecoverTo') -and [string]::IsNullOrWhiteSpace($OutputPath)) {
        throw 'This operation needs an output path.'
    }
    $commandName = switch ($Mode) {
        'Register' { 'register' }
        'Encrypt' { 'encrypt' }
        'ViewText' { 'view-text' }
        'OpenTo' { 'open-to' }
        'RecoverTo' { 'recover-to' }
    }
    if ($Mode -notin @('ViewText', 'OpenTo')) {
        $arguments = @($commandName, $InputPath)
        if ($OutputPath) { $arguments += $OutputPath }
        & $binary @arguments
        if ($LASTEXITCODE -ne 0) { throw "PhoneKey Files exited with code $LASTEXITCODE." }
    } else {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null
        $stdout = Join-Path $workDirectory 'status.txt'
        $stderr = Join-Path $workDirectory 'error.txt'
        Remove-Item -LiteralPath $qrImage, ($qrImage + '.pending'), $approvedMarker -ErrorAction SilentlyContinue
        if ($Mode -eq 'OpenTo') {
            Write-Host "This will leave an unencrypted copy at $OutputPath."
            if (!$TemporaryOpen -and (Read-Host 'Type EXPORT to continue') -cne 'EXPORT') {
                throw 'Plaintext export cancelled.'
            }
            $env:PHONEKEY_FILE_EXPORT_CONFIRMED = '1'
        }
        $env:PHONEKEY_FILE_QR_BMP = $qrImage
        $env:PHONEKEY_FILE_APPROVED_MARKER = $approvedMarker
        $env:PHONEKEY_FILE_TEXT_VIEWER = Join-Path $PSScriptRoot 'Show-PhoneKeyText.ps1'
        $arguments = @($commandName, ('"' + $InputPath + '"'))
        if ($Mode -eq 'OpenTo') { $arguments += ('"' + $OutputPath + '"') }
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $binary
        $startInfo.Arguments = $arguments -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $worker = New-Object System.Diagnostics.Process
        $worker.StartInfo = $startInfo
        [void]$worker.Start()
        $stdoutTask = $worker.StandardOutput.ReadToEndAsync()
        $stderrTask = $worker.StandardError.ReadToEndAsync()
        $form = $null
        $picture = $null
        $timer = $null
        try {
            for ($attempt = 0; $attempt -lt 100 -and !(Test-Path -LiteralPath $qrImage) -and !$worker.HasExited; $attempt++) {
                Start-Sleep -Milliseconds 100
            }
            if (!(Test-Path -LiteralPath $qrImage)) {
                if (!$worker.HasExited) { $worker.Kill() }
                throw "Could not create a file QR: $($stderrTask.Result)"
            }
            $expiresAtMs = [long](Get-Content -LiteralPath $expiryPath -Raw)
            $form = New-Object System.Windows.Forms.Form
            $form.Text = 'PhoneKey Files - scan this QR'
            $form.StartPosition = 'CenterScreen'
            $form.ClientSize = New-Object System.Drawing.Size(440, 490)
            $form.TopMost = $true
            $label = New-Object System.Windows.Forms.Label
            $label.Dock = 'Top'
            $label.Height = 40
            $label.TextAlign = 'MiddleCenter'
            $label.Text = 'Scan with PhoneKey, then approve on your phone'
            $picture = New-Object System.Windows.Forms.PictureBox
            $picture.Dock = 'Fill'
            $picture.SizeMode = 'CenterImage'
            $picture.Image = [System.Drawing.Image]::FromFile($qrImage)
            $form.Controls.Add($picture)
            $form.Controls.Add($label)
            $timer = New-Object System.Windows.Forms.Timer
            $timer.Interval = 250
            $timer.Add_Tick({
                $remaining = [Math]::Max(0, [Math]::Ceiling(
                    ($expiresAtMs - [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) / 1000.0))
                $label.Text = "Scan with PhoneKey - $remaining seconds left"
                if ($worker.HasExited -or (Test-Path -LiteralPath $approvedMarker) -or $remaining -eq 0) {
                    $form.Close()
                }
            })
            $timer.Start()
            [void]$form.ShowDialog()
        } finally {
            if ($timer) { $timer.Stop(); $timer.Dispose() }
            if ($picture -and $picture.Image) { $picture.Image.Dispose() }
            if ($form) { $form.Dispose() }
            if (!$worker.HasExited -and (Test-Path -LiteralPath $approvedMarker)) {
                if ($Mode -eq 'ViewText') {
                    Write-Host 'Phone approved. Close the text viewer when finished.'
                } else {
                    Write-Host 'Phone approved. Checking the file; larger files may take a while.'
                }
                while (!$worker.WaitForExit(5000)) {
                    if ($Mode -ne 'ViewText') { Write-Host 'Still checking the file...' }
                }
            } elseif (!$worker.HasExited) {
                [void]$worker.WaitForExit(1500)
                if (!$worker.HasExited) {
                    Stop-Process -Id $worker.Id -ErrorAction SilentlyContinue
                }
            }
            $worker.WaitForExit()
            $worker.Refresh()
            [System.IO.File]::WriteAllText($stdout, $stdoutTask.Result)
            [System.IO.File]::WriteAllText($stderr, $stderrTask.Result)
            Remove-Item -LiteralPath $qrImage, ($qrImage + '.pending'), $expiryPath, $approvedMarker -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout }
        if ($worker.ExitCode -ne 0) {
            throw "PhoneKey file opening failed (worker exit $($worker.ExitCode)): $(Get-Content -LiteralPath $stderr -Raw)"
        }
    }
    [System.IO.File]::WriteAllText($result, "$Mode succeeded")
    exit 0
} catch {
    [System.IO.File]::WriteAllText($result, "$Mode failed: $($_.Exception.Message)")
    Write-Error $_
    exit 1
}
