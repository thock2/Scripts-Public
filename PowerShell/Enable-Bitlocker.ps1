function Enable-Bitlocker {
    #Enable Bitlocker
    $disk_status = Get-BitlockerVolume $credential | Where-Object VolumeType -eq "OperatingSystem"

    if ($disk_status.VolumeStatus -eq "FullyEncrypted") {
        Write-Output "Already Encrypted"
    }
    else {
        Enable-Bitlocker -MountPoint c: -SkipHardwareTest -RecoveryPasswordProtector
        #From https://docs.microsoft.com/en-us/powershell/module/bitlocker/backup-bitlockerkeyprotector?view=win10-ps
        $BLV = Get-BitLockerVolume -MountPoint "C:"
        Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
        Write-Output "Not previously encrypted, encrypting now"
    }
}

Enable-Bitlocker