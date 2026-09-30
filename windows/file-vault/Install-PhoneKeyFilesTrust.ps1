# One-time, elevated copy of PUBLIC pairing keys for the separate file tool.
# The Windows sign-in service's state is read only and never modified here.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This one-time pairing setup needs an elevated PowerShell window.'
}
$source = Join-Path $env:PROGRAMDATA 'PhoneKey\state'
$root = Join-Path $env:PROGRAMDATA 'PhoneKeyFiles'
$destination = Join-Path $root 'trust'

foreach ($name in @('trusted_phone.json', 'windows_identity.json')) {
    $path = Join-Path $source $name
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "PhoneKey sign-in pairing is missing: $path" }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing a linked pairing file: $path" }
    if ($item.Length -gt 4096) { throw "Pairing file is too large: $path" }
    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($record.version -ne 1) { throw "Unsupported pairing version: $path" }
    if ($name -eq 'trusted_phone.json') {
        if ($record.android_device_id_hex -notmatch '^[0-9a-fA-F]{32}$' -or
            $record.public_key_sec1_hex -notmatch '^04[0-9a-fA-F]{128}$') { throw 'Invalid phone public pairing.' }
    } elseif ($record.windows_device_id_hex -notmatch '^[0-9a-fA-F]{32}$') {
        throw 'Invalid Windows public pairing.'
    }
}

$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$propagate = [Security.AccessControl.PropagationFlags]::None
foreach ($entry in @(@($system, [Security.AccessControl.FileSystemRights]::FullControl),
                    @($admins, [Security.AccessControl.FileSystemRights]::FullControl),
                    @($users, [Security.AccessControl.FileSystemRights]::ReadAndExecute))) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($entry[0], $entry[1], $inherit, $propagate, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
if (Test-Path -LiteralPath $root) {
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing linked setup folder: $root" }
    $owner = ([IO.Directory]::GetAccessControl($root)).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($system.Value, $admins.Value)) { throw "Refusing setup folder with an untrusted owner: $root" }
    [IO.Directory]::SetAccessControl($root, $acl)
} else {
    [void][IO.Directory]::CreateDirectory($root, $acl)
}
if (Test-Path -LiteralPath $destination) {
    $item = Get-Item -LiteralPath $destination -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing linked trust folder: $destination" }
    $owner = ([IO.Directory]::GetAccessControl($destination)).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($system.Value, $admins.Value)) { throw "Refusing trust folder with an untrusted owner: $destination" }
    [IO.Directory]::SetAccessControl($destination, $acl)
} else {
    [void][IO.Directory]::CreateDirectory($destination, $acl)
}
foreach ($name in @('trusted_phone.json', 'windows_identity.json')) {
    $target = Join-Path $destination $name
    if (Test-Path -LiteralPath $target) {
        $item = Get-Item -LiteralPath $target -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing linked trust file: $target" }
    }
    $bytes = [IO.File]::ReadAllBytes((Join-Path $source $name))
    [IO.File]::WriteAllBytes($target, $bytes)
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetOwner($admins)
    $fileAcl.SetAccessRuleProtection($true, $false)
    foreach ($entry in @(@($system, [Security.AccessControl.FileSystemRights]::FullControl),
                        @($admins, [Security.AccessControl.FileSystemRights]::FullControl),
                        @($users, [Security.AccessControl.FileSystemRights]::Read))) {
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($entry[0], $entry[1], [Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.File]::SetAccessControl($target, $fileAcl)
}
Write-Host 'PhoneKey Files public pairing installed. Windows sign-in pairing was not changed.'
