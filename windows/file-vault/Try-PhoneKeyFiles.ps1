param(
    [ValidateSet('Encrypt', 'ViewText', 'OpenTo', 'RecoverTo')]
    [string]$Mode = 'Encrypt'
)

$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'Run-PhoneKeyFiles.ps1'
$binary = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\release\phonekey-files.exe'))

try {
    if (!(Test-Path -LiteralPath $launcher -PathType Leaf) -or
        !(Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw 'PhoneKey Files has not been built on this laptop.'
    }

    Add-Type -AssemblyName System.Windows.Forms
    $picker = New-Object System.Windows.Forms.OpenFileDialog
    $picker.Title = if ($Mode -eq 'Encrypt') { 'Choose a COPY of a file to encrypt' } else { 'Choose an encrypted PhoneKey file' }
    $picker.Filter = if ($Mode -eq 'Encrypt') { 'All files (*.*)|*.*' } else { 'PhoneKey files (*.pkp)|*.pkp' }
    if ($Mode -eq 'Encrypt') {
        $picker.InitialDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\file-vault-ui'))
    }
    $picker.CheckFileExists = $true
    if ($picker.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host 'No file selected.'
        return
    }
    $inputPath = [System.IO.Path]::GetFullPath($picker.FileName)
    if ($Mode -eq 'Encrypt' -and (Get-Item -LiteralPath $inputPath).Length -gt 1TB) {
        throw 'This version accepts files up to 1 TiB. Choose a smaller disposable copy.'
    }

    if ($Mode -eq 'ViewText') {
        Write-Host 'Open PhoneKey on your phone and scan the fresh QR; approve with your fingerprint.'
        & $launcher -Mode ViewText -InputPath $inputPath
        if ($LASTEXITCODE -ne 0) { throw 'PhoneKey Files did not open the file.' }
        return
    }

    $save = New-Object System.Windows.Forms.SaveFileDialog
    $save.Title = switch ($Mode) {
        'Encrypt' { 'Save the NEW encrypted copy' }
        'OpenTo' { 'Save a NEW phone-approved plaintext copy' }
        default { 'Save a NEW recovered plaintext copy' }
    }
    $save.FileName = if ($Mode -eq 'Encrypt') {
        [System.IO.Path]::GetFileName($inputPath) + '.pkp'
    } elseif ($Mode -eq 'OpenTo') {
        $originalName = [System.IO.Path]::GetFileNameWithoutExtension($inputPath)
        $originalExtension = [System.IO.Path]::GetExtension($originalName)
        [System.IO.Path]::GetFileNameWithoutExtension($originalName) + '.PhoneKey-opened' + $originalExtension
    } else {
        [System.IO.Path]::GetFileNameWithoutExtension($inputPath) + '.recovered'
    }
    $save.InitialDirectory = [System.IO.Path]::GetDirectoryName($inputPath)
    $save.OverwritePrompt = $true
    if ($save.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host 'No output selected.'
        return
    }
    $outputPath = [System.IO.Path]::GetFullPath($save.FileName)
    if (Test-Path -LiteralPath $outputPath) {
        throw 'That output already exists. PhoneKey Files will not replace it.'
    }

    if ($Mode -eq 'Encrypt') {
        Write-Host 'The original file stays unencrypted. Save the recovery code separately and type it again when asked.'
    } elseif ($Mode -eq 'RecoverTo') {
        Write-Host 'Recovery creates an unencrypted copy. Enter the saved recovery code; then type EXPORT.'
    } else {
        Write-Host 'PhoneKey opening creates an unencrypted copy. Type EXPORT, then scan the QR and approve with your fingerprint.'
    }
    & $launcher -Mode $Mode -InputPath $inputPath -OutputPath $outputPath
    if ($LASTEXITCODE -ne 0) { throw 'PhoneKey Files did not complete the operation.' }
    Write-Host "Completed: $outputPath"
} catch {
    Write-Error $_
    exit 1
}
