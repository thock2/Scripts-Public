[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('user')]
    [string]$username
)
$InformationPreference = 'Continue'
# Asks for the username. It uses the first.last naming convention found in C:\Users
# Replaced with parameter to include name from start
# $username = Read-Host 'Username?'

# Checks for 7zip. If it is installed, the backup will start. If not, It will install it
# I'm using 7z to create an archive of the chrome profile because it normally is
# thousands of small files that add up to 9+GB sometimes, copying them normally is a pain

$software = "7-Zip 19.00 (x64)";
$installed = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $software })

If (-Not $installed) {
    Start-Process '\\Some_Server\7z1900-x64.msi' "/quiet" -Wait
    ;
}
else {
    Write-Information "'$software' is installed. Starting Backup."
}

# These store locations of things to be backed up in variables
$Desktop = "C:\Users\$username\Desktop"
$Documents = "C:\Users\$username\Documents"
$Downloads = "C:\Users\$username\Downloads"
$Pictures = "C:\Users\$username\Pictures"
$Chrome = "C:\Users\$username\AppData\Local\Google\Chrome\User Data\Default"
# $Firefox = "C:\Users\$username\AppData\Local\Mozilla\Firefox\Profiles"
# $Edge = "C:\Users\$username\AppData\Local\Microsoft\Edge\User Data\Default"
# $Videos = "C:\Users\$username\Videos"

# Change $destination_path to wherever you want to save these backups
$destination_path = "\\Some_Server\$username@yourdomain.local"

# Copies all user files in the listed locations to the network drive

Write-Information "Copying Desktop..."; robocopy "$Desktop" "$destination_path\Desktop" /E
Start-Sleep -Seconds 5
Clear-Host

Write-Information "Copying Documents..."; robocopy "$Documents" "$destination_path\Documents" /E
Start-Sleep -Seconds 5
Clear-Host

Write-Information "Copying Downloads..."; robocopy "$Downloads" "$destination_path\Downloads" /E
Start-Sleep -Seconds 5
Clear-Host

Write-Information "Copying Pictures..."; robocopy "$Pictures" "$destination_path\Pictures" /E
Start-Sleep -Seconds 5
Clear-Host

# Copies the chrome profile
Write-Information "Copying Chrome Profile..."; & 'C:\Program Files\7-Zip\7z.exe' a -t7z "$destination_path\Default.7z" "$Chrome"

Write-Information "Complete!"

# Nobody seems to have videos, so this has been commented out. If the user has videos, just uncomment this portion.
# Write-Information "Copying Videos..."
# robocopy "$Videos" "$destination_path\Videos" /E