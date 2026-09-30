# Run as the signed-in user. Only the public pairing copy requests one UAC approval.
$ErrorActionPreference = 'Stop'
$trustSetup = Join-Path $PSScriptRoot 'Install-PhoneKeyFilesTrust.ps1'
$launcher = Join-Path $PSScriptRoot 'Invoke-PhoneKeyFile.ps1'
$binary = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\release\phonekey-files.exe'))
if (!(Test-Path -LiteralPath $launcher -PathType Leaf) -or !(Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'PhoneKey Files is not built on this laptop.'
}
$trust = Join-Path $env:PROGRAMDATA 'PhoneKeyFiles\trust'
if (!(Test-Path -LiteralPath (Join-Path $trust 'trusted_phone.json') -PathType Leaf) -or
    !(Test-Path -LiteralPath (Join-Path $trust 'windows_identity.json') -PathType Leaf)) {
    Write-Host 'One-time Windows approval is needed to copy the public phone pairing for PhoneKey Files.'
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $trustSetup + '"'))
    if ($process.ExitCode -ne 0) { throw "PhoneKey Files pairing setup failed (exit $($process.ExitCode))." }
}
foreach ($name in @('trusted_phone.json', 'windows_identity.json')) {
    if (!(Test-Path -LiteralPath (Join-Path $trust $name) -PathType Leaf)) {
        throw "PhoneKey Files pairing setup did not create $name."
    }
}

$classes = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Classes')
try {
    $extension = $classes.OpenSubKey('.pkp', $false)
    if ($extension) {
        $current = $extension.GetValue('')
        $extension.Dispose()
        if ($current -and $current -ne 'PhoneKey.Package') {
            throw ".pkp is already associated with $current; its existing app was not changed."
        }
    }
    # Always launch the Windows-installed PowerShell. The installer may run
    # inside a bundled tool runtime whose PSHOME is isolated from Explorer.
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (!(Test-Path -LiteralPath $powershell -PathType Leaf)) {
        throw 'Windows PowerShell is unavailable.'
    }
    $base = '"' + $powershell + '" -NoProfile -STA -ExecutionPolicy Bypass -File "' + $launcher + '"'
    $openCommand = $base + ' -Mode Open -InputPath "%1"'

    # This Windows build filters per-user static file verbs from Explorer's
    # visible menu even though Shell.Application lists them. Remove our own
    # invisible registrations rather than claiming that they work.
    foreach ($path in @('*\shell\PhoneKey.Encrypt',
                       'AllFileSystemObjects\shell\PhoneKey.Encrypt',
                       'SystemFileAssociations\.txt\shell\PhoneKey.Encrypt',
                       'SystemFileAssociations\.txt\shell\PhoneKeyMenuProbe')) {
        if ($classes.OpenSubKey($path)) { $classes.DeleteSubKeyTree($path, $false) }
    }

    $entry = $classes.CreateSubKey('.pkp')
    $entry.SetValue('', 'PhoneKey.Package')
    $entry.Dispose()
    $entry = $classes.CreateSubKey('PhoneKey.Package')
    $entry.SetValue('', 'PhoneKey encrypted file')
    $entry.Dispose()
    $entry = $classes.CreateSubKey('PhoneKey.Package\shell\open\command')
    $entry.SetValue('', $openCommand)
    $entry.Dispose()
} finally {
    $classes.Dispose()
}
$sendTo = [Environment]::GetFolderPath([Environment+SpecialFolder]::SendTo)
if ([string]::IsNullOrWhiteSpace($sendTo) -or !(Test-Path -LiteralPath $sendTo -PathType Container)) {
    throw 'Windows Send to folder is unavailable for this account.'
}
$shortcutPath = Join-Path $sendTo 'Encrypt with PhoneKey.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $powershell
$shortcut.Arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File "' + $launcher + '" -Mode Encrypt -InputPath'
$shortcut.WorkingDirectory = $PSScriptRoot
$shortcut.Description = 'Encrypt the selected file with PhoneKey'
$shortcut.Save()
$hotkeyLauncher = Join-Path $PSScriptRoot 'Invoke-PhoneKeySelectedFile.ps1'
$programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
if (!(Test-Path -LiteralPath $hotkeyLauncher -PathType Leaf) -or
    [string]::IsNullOrWhiteSpace($programs) -or
    !(Test-Path -LiteralPath $programs -PathType Container)) {
    throw 'The PhoneKey keyboard shortcut cannot be installed for this account.'
}
$hotkeyPath = Join-Path $programs 'Encrypt selected file with PhoneKey.lnk'
$hotkey = $shell.CreateShortcut($hotkeyPath)
$hotkey.TargetPath = $powershell
$hotkey.Arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File "' + $hotkeyLauncher + '"'
$hotkey.WorkingDirectory = $PSScriptRoot
$hotkey.Description = 'Encrypt one selected file with PhoneKey'
$hotkey.Hotkey = 'CTRL+SHIFT+P'
$hotkey.Save()
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PhoneKeyShellRefresh {
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
}
'@
# File Explorer caches verbs and file associations. Tell it to reload both.
[PhoneKeyShellRefresh]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host 'Installed: right-click a file > Show more options > Send to > Encrypt with PhoneKey.'
Write-Host 'You can also select one file and press Ctrl+Shift+P. If no file is selected, a file picker opens.'
Write-Host 'Double-click a .pkp file to scan its QR and open it after fingerprint approval.'
