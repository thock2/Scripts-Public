[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Alias('newname')]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $true)]
    [Alias('Domain')]
    [string[]]$domainname
)
# Set time zone to central because microsoft puts pacific as default for some reason
Set-TimeZone -Name "Central Standard Time"
# Add Computer to Domain
Add-Computer -NewName $ComputerName -DomainName $DomainName -DomainCredential (Get-Credential) -Verbose

# Enable WinRM
# Checks if service is running, if not, identify adapter and change profile to private, enable winrm
function enable-winrm {
    $winrm_status = Get-Service WinRM | Select-Object Status
    if ($winrm_status -eq "Running") {
        break
    }
    else {
        $interface = Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory
        if ($interface.NetworkCategory -match "DomainAuthenticated" -or $interface.NetworkCategory -match "Private") {
            winrm quickconfig -q
        }
        else {
            Set-NetConnectionProfile -InterfaceAlias $interface.InterfaceAlias -NetworkCategory Private
            winrm quickconfig -q
        }
    }
}

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

# Install PSWindowsUpdate Module 
function install-pswindowsupdate {
    Install-PackageProvider NuGet -Force; Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module -Name PSWindowsUpdate
}

enable-winrm
Enable-Bitlocker
install-pswindowsupdate