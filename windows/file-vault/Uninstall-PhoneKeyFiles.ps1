param([switch]$ElevatedTrustOnly)

# Removes only the separate PhoneKey Files pilot. Never touches PhoneKeyService,
# the Credential Provider, or the sign-in state under ProgramData\PhoneKey.
$ErrorActionPreference = 'Stop'

function Remove-EmptyDirectory([string]$path) {
    if (!(Test-Path -LiteralPath $path -PathType Container)) { return }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing linked directory: $path"
    }
    if (@(Get-ChildItem -LiteralPath $path -Force).Count -eq 0) {
        Remove-Item -LiteralPath $path -Force
    }
}

if ($ElevatedTrustOnly) {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Removing the PhoneKey Files trust copy requires Administrator.'
    }
    $root = Join-Path $env:PROGRAMDATA 'PhoneKeyFiles'
    $trust = Join-Path $root 'trust'
    foreach ($path in @($root, $trust)) {
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing linked PhoneKey Files folder: $path"
            }
        }
    }
    foreach ($name in @('trusted_phone.json', 'windows_identity.json')) {
        $path = Join-Path $trust $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing linked PhoneKey Files trust file: $path"
            }
            Remove-Item -LiteralPath $path -Force
        }
    }
    Remove-EmptyDirectory $trust
    Remove-EmptyDirectory $root
    Write-Host 'Removed the separate PhoneKey Files trust copy.'
    exit 0
}

$sendTo = [Environment]::GetFolderPath([Environment+SpecialFolder]::SendTo)
$programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
foreach ($path in @((Join-Path $sendTo 'Encrypt with PhoneKey.lnk'),
                   (Join-Path $programs 'Encrypt selected file with PhoneKey.lnk'))) {
    if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
}

$classes = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Classes', $true)
if ($classes) {
    try {
        $extension = $classes.OpenSubKey('.pkp')
        if ($extension) {
            $owned = $extension.GetValue('') -eq 'PhoneKey.Package'
            $extension.Dispose()
            if ($owned) { $classes.DeleteSubKeyTree('.pkp', $false) }
        }
        $package = $classes.OpenSubKey('PhoneKey.Package')
        if ($package) {
            $owned = $package.GetValue('') -eq 'PhoneKey encrypted file'
            $package.Dispose()
            if ($owned) { $classes.DeleteSubKeyTree('PhoneKey.Package', $false) }
        }
    } finally { $classes.Dispose() }
}

$local = Join-Path $env:LOCALAPPDATA 'PhoneKey\file-vault'
$binding = Join-Path $local 'signed-binding.txt'
if (Test-Path -LiteralPath $binding -PathType Leaf) { Remove-Item -LiteralPath $binding -Force }
$sessions = Join-Path $local 'session'
if (Test-Path -LiteralPath $sessions -PathType Container) {
    foreach ($session in Get-ChildItem -LiteralPath $sessions -Force -Directory) {
        if (($session.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $session.FullName -Force -File) {
            if ($file.Name -in @('status.txt', 'error.txt')) {
                Remove-Item -LiteralPath $file.FullName -Force
            }
        }
        Remove-EmptyDirectory $session.FullName
    }
}
Remove-EmptyDirectory $sessions
Remove-EmptyDirectory (Join-Path $local 'opened')
Remove-EmptyDirectory $local

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PhoneKeyFilesShellRefresh {
    [DllImport("shell32.dll")] public static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
}
'@
[PhoneKeyFilesShellRefresh]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host 'Removed PhoneKey Files shortcuts, hotkey, file association, and local pairing copy.'
Write-Host 'Existing documents and .pkp files were preserved. Windows sign-in was not changed.'
