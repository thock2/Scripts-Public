$credential = (Get-Credential)
$disk_status = Get-BitlockerVolume $credential | Where-Object VolumeType -eq "OperatingSystem"

if ($disk_status.VolumeStatus -eq "FullyEncrypted") {
    Write-Output "Already Encrypted"
}else {
    Enable-Bitlocker -MountPoint c: -SkipHardwareTest -RecoveryPasswordProtector
    Write-Output "Encrypting...."
}
