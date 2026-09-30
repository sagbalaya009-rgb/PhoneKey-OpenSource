# Exercises the exact Send to launcher with a disposable file; never prints the recovery code.
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'Invoke-PhoneKeyFile.ps1'
$directory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\file-vault-ui'))
[void][IO.Directory]::CreateDirectory($directory)
$source = Join-Path $directory ('PhoneKey Send to test ' + [guid]::NewGuid().ToString('N') + '.txt')
$encrypted = $source + '.pkp'
$code = $null
$process = $null
try {
    [IO.File]::WriteAllText($source, 'PHONEKEY DUMMY ONLY - disposable Send to test')
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = 'powershell.exe'
    $info.Arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File "' + $launcher + '" -Mode Encrypt -InputPath "' + $source + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    [void]$process.Start()
    while ($true) {
        $line = $process.StandardOutput.ReadLine()
        if ($null -eq $line) { break }
        if ($line -match '^PKRC1-(?:[0-9a-f]{8}-){7}[0-9a-f]{8}$') {
            $code = $line
            break
        }
    }
    if (!$code) { throw "Send to did not reach the recovery-code step: $($process.StandardError.ReadToEnd())" }
    $process.StandardInput.WriteLine($code)
    $process.StandardInput.Close()
    [void]$process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -or !(Test-Path -LiteralPath $encrypted -PathType Leaf)) {
        throw "Send to encryption failed: $stderr"
    }
    Write-Host 'The Send to launcher encrypted a disposable file successfully.'
} finally {
    $code = $null
    if ($process) { if (!$process.HasExited) { $process.Kill() }; $process.Dispose() }
    foreach ($item in @($encrypted, $source)) {
        if (Test-Path -LiteralPath $item) { Remove-Item -LiteralPath $item -Force }
    }
}
