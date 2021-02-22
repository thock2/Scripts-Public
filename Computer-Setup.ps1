$InformationPreference = 'Continue'
# Domain gets credentials for New-PSDrive and domain join
$DomainCredential = Get-Credential -Credential #Domain Credential

# Set time zone to central because microsoft puts pacific as default for some reason
Set-TimeZone -Name "Central Standard Time"

# Ask for Computer name, Rename to specified name, Join domain
$ComputerName = Read-Host "What will this computer be named?"
$DomainName = 'Domain Name'
Add-Computer -NewName $ComputerName -DomainName $DomainName -DomainCredential $DomainCredential -Verbose

# Connects to share drive for access to installers
New-PSDrive -Name "X" -Root "\\Some_Server\Software" -PSProvider "Filesystem" -Credential $DomainCredential

# Example of install from share drive
# $acrobat = '\\Some_Server\Software\AcroRdrDC2001320074_en_US\setup.exe"
# Start-Process $acrobat "/sAll" -Wait 

## Install chocolatey: https://chocolatey.org/
# From: https://chocolatey.org/courses/installation/installing?method=install-from-powershell-v3?quiz=true
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-WebRequest https://chocolatey.org/install.ps1 -UseBasicParsing | Invoke-Expression

choco install 7zip.install googlechrome zoom teamviewer office365business -y

# Enable WinRM
# Checks if service is running, if not, identify adapter and change profile to private, enable winrm
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

# Install PSWindowsUpdate Module for remote update management
Install-PackageProvider NuGet -Force; Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module -Name PSWindowsUpdate
Import-Module PSWindowsUpdate
#Enables automatic updates
Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7 -Confirm:$false
#Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -Verbose