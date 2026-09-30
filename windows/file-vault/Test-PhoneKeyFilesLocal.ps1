# Disposable end-to-end encryption and recovery check. Never prints the recovery code.
$ErrorActionPreference = 'Stop'
$binary = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\release\phonekey-files.exe'))
$launcher = Join-Path $PSScriptRoot 'Run-PhoneKeyFiles.ps1'
$directory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\file-vault-ui'))
[void][IO.Directory]::CreateDirectory($directory)
$stem = 'PhoneKey explorer smoke ' + [guid]::NewGuid().ToString('N')
$source = Join-Path $directory ($stem + '.txt')
$encrypted = $source + '.pkp'
$recovered = Join-Path $directory ($stem + '.recovered.txt')
$code = $null
function Start-FileTool([string]$arguments, [bool]$useLauncher = $false) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = if ($useLauncher) { 'powershell.exe' } else { $binary }
    $info.Arguments = $arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    [void]$process.Start()
    return $process
}
try {
    [IO.File]::WriteAllText($source, 'PHONEKEY DUMMY ONLY - disposable Explorer encryption test')
    $process = Start-FileTool ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '" -Mode Encrypt -InputPath "' + $source + '" -OutputPath "' + $encrypted + '"') $true
    $header = $process.StandardOutput.ReadLine()
    $code = $process.StandardOutput.ReadLine()
    if ($header -notlike 'Save this recovery code*' -or
        $code -notmatch '^PKRC1-(?:[0-9a-f]{8}-){7}[0-9a-f]{8}$') {
        throw "Encrypt did not reach recovery-code confirmation: $($process.StandardError.ReadToEnd())"
    }
    $process.StandardInput.WriteLine($code)
    $process.StandardInput.Close()
    $output = $process.StandardOutput.ReadToEnd()
    $errorText = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -or !(Test-Path -LiteralPath $encrypted -PathType Leaf)) {
        throw "Disposable encryption failed: $errorText"
    }
    $process.Dispose()

    $process = Start-FileTool ('recover-to "' + $encrypted + '" "' + $recovered + '"')
    $process.StandardInput.WriteLine($code)
    $process.StandardInput.WriteLine('EXPORT')
    $process.StandardInput.Close()
    $output = $process.StandardOutput.ReadToEnd()
    $errorText = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -or !(Test-Path -LiteralPath $recovered -PathType Leaf)) {
        throw "Disposable recovery failed: $errorText"
    }
    $process.Dispose()
    $originalHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $recoveredHash = (Get-FileHash -LiteralPath $recovered -Algorithm SHA256).Hash
    if ($originalHash -ne $recoveredHash) { throw 'Recovered disposable file did not match its source.' }
    Write-Host 'Disposable PhoneKey Files encryption and recovery passed under this Windows user.'
} finally {
    $code = $null
    foreach ($path in @($recovered, $encrypted, $source)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
}
