param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Encrypt', 'Open')]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$InputPath
)

$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'Run-PhoneKeyFiles.ps1'
$openedFolder = $null
$opened = $false
try {
    if (!(Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw "File not found: $InputPath" }
    $path = [IO.Path]::GetFullPath($InputPath)
    if ($Mode -eq 'Encrypt') {
        if ([IO.Path]::GetExtension($path) -ieq '.pkp') { throw 'This file is already a PhoneKey package.' }
        $output = $path + '.pkp'
        if (Test-Path -LiteralPath $output) { throw "Encrypted copy already exists: $output" }
        $binary = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\release\phonekey-files.exe'))
        $binding = Join-Path $env:LOCALAPPDATA 'PhoneKey\file-vault\signed-binding.txt'
        $export = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\file-binding-export.txt'))
        $previousErrorAction = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $setupOutput = & $binary check-setup 2>&1 | Out-String }
        finally { $ErrorActionPreference = $previousErrorAction }
        if ($LASTEXITCODE -ne 0) {
            if (!(Test-Path -LiteralPath $export -PathType Leaf)) {
                throw "PhoneKey Files pairing is unavailable for $([Security.Principal.WindowsIdentity]::GetCurrent().Name). The signed phone binding needs to be registered again. $setupOutput"
            }
            Write-Host 'Restoring the verified PhoneKey Files pairing for this Windows account.'
            $ErrorActionPreference = 'Continue'
            try { $registerOutput = & $binary register $export 2>&1 | Out-String }
            finally { $ErrorActionPreference = $previousErrorAction }
            if ($LASTEXITCODE -ne 0) {
                throw "PhoneKey Files pairing could not be restored for $([Security.Principal.WindowsIdentity]::GetCurrent().Name). Local binding exists: $([IO.File]::Exists($binding)). $registerOutput"
            }
            $ErrorActionPreference = 'Continue'
            try { $setupOutput = & $binary check-setup 2>&1 | Out-String }
            finally { $ErrorActionPreference = $previousErrorAction }
            if ($LASTEXITCODE -ne 0) {
                throw "PhoneKey Files pairing is still unavailable after verified registration. Local binding exists: $([IO.File]::Exists($binding)). $setupOutput"
            }
        }
        Write-Host "Encrypting: $path"
        Write-Host "Encrypted copy: $output"
        Write-Host 'The original remains unencrypted. Save the recovery code separately and re-enter it to finish.'
        & $launcher -Mode Encrypt -InputPath $path -OutputPath $output
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $output -PathType Leaf)) {
            throw 'Encryption did not complete. The original file was not changed.'
        }
        Write-Host "Encrypted copy verified: $output"
        Write-Host 'The original is still unencrypted. Keep it until you have safely stored your recovery code and tested opening the encrypted copy.'
        return
    }

    if ([IO.Path]::GetExtension($path) -ine '.pkp') { throw 'Choose a .pkp encrypted file.' }
    $originalName = [IO.Path]::GetFileNameWithoutExtension($path)
    if ([string]::IsNullOrWhiteSpace($originalName)) { throw 'Encrypted file has no original filename.' }
    $openedFolder = Join-Path $env:LOCALAPPDATA ('PhoneKey\file-vault\opened\' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($openedFolder)
    $plaintext = Join-Path $openedFolder $originalName
    Write-Host 'Scan the QR with PhoneKey and approve with your fingerprint.'
    Write-Host 'Windows needs a temporary unencrypted copy to open this file in its usual app.'
    $resultPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\file-vault-ui-result.txt'))
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            & $launcher -Mode OpenTo -InputPath $path -OutputPath $plaintext -TemporaryOpen
        } catch {
            Write-Host "PhoneKey Files attempt failed: $($_.Exception.Message)"
        }
        if (Test-Path -LiteralPath $plaintext -PathType Leaf) { break }
        $result = if (Test-Path -LiteralPath $resultPath) { Get-Content -LiteralPath $resultPath -Raw } else { '' }
        if ($attempt -eq 0 -and $result -like '*GATT service discovery failed after retries*') {
            Write-Host 'Bluetooth service was temporarily unavailable. Showing a fresh QR automatically.'
            continue
        }
        break
    }
    if (!(Test-Path -LiteralPath $plaintext -PathType Leaf)) {
        throw 'Phone approval or file verification did not complete; no document was opened.'
    }
    Write-Host "Opening: $originalName"
    Start-Process -FilePath $plaintext | Out-Null
    $opened = $true
    Add-Type -AssemblyName System.Windows.Forms
    while ($true) {
        [void][Windows.Forms.MessageBox]::Show(
            "Close $originalName in its app, then click OK to remove its temporary unencrypted copy. Keep this window open until cleanup succeeds.",
            'PhoneKey Files - finish opening',
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Information
        )
        try {
            Remove-Item -LiteralPath $plaintext -Force -ErrorAction Stop
            Remove-Item -LiteralPath $openedFolder -Force -ErrorAction Stop
            $openedFolder = $null
            Write-Host 'Temporary unencrypted copy removed.'
            break
        } catch {
            $choice = [Windows.Forms.MessageBox]::Show(
                "The document is still in use. Close it and choose Retry. Choosing Cancel leaves an unencrypted temporary copy at $plaintext.",
                'PhoneKey Files - cleanup',
                [Windows.Forms.MessageBoxButtons]::RetryCancel,
                [Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($choice -ne [Windows.Forms.DialogResult]::Retry) { break }
        }
    }
} catch {
    try {
        $diagnostic = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\file-vault-ui\user-launch-diagnostic.txt'))
        $bindingPath = Join-Path $env:LOCALAPPDATA 'PhoneKey\file-vault\signed-binding.txt'
        $details = @(
            "Time=$([DateTimeOffset]::Now.ToString('o'))",
            "User=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)",
            "SID=$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)",
            "LocalAppData=$env:LOCALAPPDATA",
            "BindingDirectoryExists=$([IO.Directory]::Exists([IO.Path]::GetDirectoryName($bindingPath)))",
            "BindingFileExists=$([IO.File]::Exists($bindingPath))",
            "Error=$($_.Exception.Message)"
        )
        [IO.File]::WriteAllLines($diagnostic, $details)
    } catch {}
    Write-Host "PhoneKey Files error: $($_.Exception.Message)" -ForegroundColor Red
    Add-Type -AssemblyName System.Windows.Forms
    [void][Windows.Forms.MessageBox]::Show(
        $_.Exception.Message,
        'PhoneKey Files could not finish',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    )
    if ($openedFolder -and (Test-Path -LiteralPath $openedFolder)) {
        if (!$opened) {
            Get-ChildItem -LiteralPath $openedFolder -File -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $openedFolder -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "Temporary plaintext may remain at: $openedFolder" -ForegroundColor Yellow
        }
    }
    exit 1
}
