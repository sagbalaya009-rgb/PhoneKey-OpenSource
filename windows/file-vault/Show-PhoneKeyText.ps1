$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# The approved bytes arrive through an anonymous pipe. No plaintext path or
# command-line argument is created for ordinary text viewing.
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$content = [Console]::In.ReadToEnd()
$form = New-Object System.Windows.Forms.Form
$form.Text = 'PhoneKey Files - approved text'
$form.StartPosition = 'CenterScreen'
$form.Width = 900
$form.Height = 650
$viewer = New-Object System.Windows.Forms.RichTextBox
$viewer.Dock = 'Fill'
$viewer.ReadOnly = $true
$viewer.WordWrap = $true
$viewer.ScrollBars = 'Both'
$viewer.Font = New-Object System.Drawing.Font('Consolas', 11)
$viewer.Text = $content
$form.Controls.Add($viewer)

try {
    [void]$form.ShowDialog()
} finally {
    $viewer.Clear()
    $viewer.Dispose()
    $form.Dispose()
    $content = $null
}
