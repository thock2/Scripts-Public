$InformationPreference = 'Continue'
# Local gets credentials for computer rename later on, 
# Domain gets credentials for New-PSDrive
$LocalCredential = Get-Credential -Credential $env:COMPUTERNAME\acadmin
$DomainCredential = Get-Credential -Credential #Domain Credential

# Set time zone to central because microsoft puts pacific as default for some reason
Set-TimeZone -Name "Central Standard Time"

# Ask for Computer name, Rename to specified name, Add to domain
$ComputerName = Read-Host "What will this computer be named?"
$DomainName = #Domain Name
Write-Information "Renaming computer..."; Rename-Computer -NewName "$ComputerName" -LocalCredential $LocalCredential
Write-Information "Adding $ComputerName to domain..."; Add-Computer -DomainName $DomainName -Credential $DomainCredential -Restart

# Connects to share drive for installation of TrendMicro
New-PSDrive -Name "X" -Root "\\Some_Server\Software" -PSProvider "Filesystem" -Credential $DomainCredential
# Trendmicro installer and arguments
$TrendMicro = '\\Some_Server\WFBS-SVC_Agent_Installer.msi'
$TrendMicro_args = 'IDENTIFIER="Found in TM account" SILENTMODE=1'

## Install chocolatey: https://chocolatey.org/
# From: https://chocolatey.org/courses/installation/installing?method=install-from-powershell-v3?quiz=true
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-WebRequest https://chocolatey.org/install.ps1 -UseBasicParsing | Invoke-Expression

choco install 7zip.install googlechrome microsoft-edge zoom teamviewer adobereader office365business -y

# TrendMicro Install 
# Followed this guide:
# https://docs.trendmicro.com/wfbs-svc/v6.7/en-us/deploy_script_identifier_group/
Write-Information "Installing TrendMicro..."; Start-Process $TrendMicro $TrendMicro_args -Wait

# Enable WinRM
# Sets network profile to Private, will fail if not set.
Write-Information "Enabling WinRM..."
$interface = Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceAlias
Set-NetConnectionProfile -InterfaceAlias $interface -NetworkCategory Private
winrm quickconfig -q

# Rename Computer
Write-Information "Renaming Computer..."; Rename-Computer -NewName "$ComputerName" -LocalCredential $LocalCredential

# Install PSWindows Update, Enable updates to be managed remotely
# Check for and Install available updates, install once done.
Install-Module -Name PSWindowsUpdate -Force
Enable-WURemoting
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot