# Ctrl+Shift+P shortcut: use a single selected Explorer file, or let the user choose one.
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'Invoke-PhoneKeyFile.ps1'
Add-Type -AssemblyName System.Windows.Forms
$candidates = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$shell = New-Object -ComObject Shell.Application
foreach ($window in $shell.Windows()) {
    try {
        if ([IO.Path]::GetFileName([string]$window.FullName) -ine 'explorer.exe') { continue }
        foreach ($item in $window.Document.SelectedItems()) {
            $candidate = [string]$item.Path
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                [void]$candidates.Add([IO.Path]::GetFullPath($candidate))
            }
        }
    } catch {
        # Some Shell windows do not expose a file selection.
    }
}
if ($candidates.Count -eq 1) {
    $path = @($candidates)[0]
} else {
    $picker = New-Object Windows.Forms.OpenFileDialog
    $picker.Title = 'Choose one file to encrypt with PhoneKey'
    $picker.Filter = 'All files (*.*)|*.*'
    $picker.Multiselect = $false
    if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { exit 0 }
    $path = $picker.FileName
}
if ([IO.Path]::GetExtension($path) -ieq '.pkp') {
    [void][Windows.Forms.MessageBox]::Show('Choose the original file to encrypt. This .pkp file is already encrypted.', 'PhoneKey Files')
    exit 1
}
& $launcher -Mode Encrypt -InputPath $path
exit $LASTEXITCODE
