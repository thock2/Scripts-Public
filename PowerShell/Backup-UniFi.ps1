$DomainCredential = Get-Credential -Credential #your domain credential account

New-PSDrive -Name "X" -Root "\\Some_Server\Unifi" -PSProvider "Filesystem" -Credential $DomainCredential

$unifi_backup_location = "$env:USERNAME\Ubiquiti UniFi\data\backup\autobackup"
$unifi_backup_destination = "\\Some_Server\Unifi\"

Write-Output "Copying..."; robocopy "$unifi_backup_location" "$unifi_backup_destination" /E
