param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Setup', 'Open')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
$buildDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target'))
$demo = Join-Path $buildDirectory 'debug\phonekey-file-demo.exe'
$binding = Join-Path $buildDirectory 'file-binding-export.txt'
$testDirectory = Join-Path $buildDirectory 'file-vault-demo'
$original = Join-Path $testDirectory 'dummy.txt'
$encrypted = Join-Path $testDirectory 'dummy.pkp'
$result = Join-Path $buildDirectory 'file-vault-demo-result.txt'
$qrImage = Join-Path $testDirectory 'file-open-qr.bmp'

function Invoke-Demo {
    param([string[]]$DemoArgs)
    & $demo @DemoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "File-vault demo failed: $($DemoArgs[0]) (exit $LASTEXITCODE)"
    }
}

try {
    if (!(Test-Path -LiteralPath $demo -PathType Leaf)) {
        throw 'The file-vault demo has not been built.'
    }
    switch ($Mode) {
        'Setup' {
            New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
            if ((Test-Path -LiteralPath $original) -or (Test-Path -LiteralPath $encrypted)) {
                throw 'Disposable demo files already exist; refusing to overwrite them.'
            }
            Invoke-Demo -DemoArgs @('register', $binding)
            Invoke-Demo -DemoArgs @('make-dummy', $original, $encrypted)
        }
        'Open' {
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            $stdout = Join-Path $testDirectory 'open-output.txt'
            $stderr = Join-Path $testDirectory 'open-error.txt'
            Remove-Item -LiteralPath $qrImage -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath ($qrImage + '.pending') -ErrorAction SilentlyContinue
            $env:PHONEKEY_FILE_QR_BMP = $qrImage
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $demo
            $startInfo.Arguments = 'open-dummy "' + $encrypted + '"'
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
                    throw "Could not create the compact QR: $($stderrTask.Result)"
                }
                $expiryPath = [System.IO.Path]::ChangeExtension($qrImage, '.expiry')
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
                $label.Text = 'Scan with PhoneKey, then approve your fingerprint'
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
                    if ($worker.HasExited -or $remaining -eq 0) { $form.Close() }
                })
                $timer.Start()
                [void]$form.ShowDialog()
            } finally {
                if ($timer) { $timer.Stop(); $timer.Dispose() }
                if ($picture -and $picture.Image) { $picture.Image.Dispose() }
                if ($form) { $form.Dispose() }
                if (!$worker.HasExited) {
                    [void]$worker.WaitForExit(1500)
                    if (!$worker.HasExited) {
                        Stop-Process -Id $worker.Id -ErrorAction SilentlyContinue
                    }
                }
                $worker.WaitForExit()
                $worker.Refresh()
                [System.IO.File]::WriteAllText($stdout, $stdoutTask.Result)
                [System.IO.File]::WriteAllText($stderr, $stderrTask.Result)
            }
            if (Test-Path -LiteralPath $stdout) {
                Get-Content -LiteralPath $stdout
            }
            if ($worker.ExitCode -ne 0) {
                throw "File opening failed (worker exit $($worker.ExitCode)): $(Get-Content -LiteralPath $stderr -Raw)"
            }
        }
    }
    [System.IO.File]::WriteAllText($result, "$Mode succeeded")
} catch {
    [System.IO.File]::WriteAllText($result, "$Mode failed: $($_.Exception.Message)")
    Write-Error $_
    exit 1
}
