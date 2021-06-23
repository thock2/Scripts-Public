<#
.SYNOPSIS
Disables a users local AD account and AzureAD account
.DESCRIPTION
You provide the username and location as parameters, and the script will run from there
.PARAMETER ad_username
Provide the users' ad username (kanye.west).
.PARAMETER user_location
Provide the office location of the user (Here, there, or everywhere)

.EXAMPLE
azure_ad-disable-user -username kanye.west -location CA

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string]$ad_username,

    [Parameter(Mandatory = $true)]
    [Alias('location')]
    [string]$user_location
)

$InformationPreference = 'Continue'

# Connect to AzureAD and Teams for online accounts
$AdminCred = Get-Credential #Your admin account
Connect-AzureAD -Credential $AdminCred

# Defines username variables (firstname.lastname)
$azure_ad_username = $ad_username + "@your_domain.com"

# Disable accounts
Write-Information "Disabling Accounts...."
# Set on-prem AD account to disabled
# Move on-prem AD to Past Employees OU

# all if else statements can probably be combined - would probably speed things up
if ($user_location -like "Here") {
    $ad_user_guid = Get-ADUser $ad_username | Select-Object -ExpandProperty ObjectGUID
    # Set on-prem AD account to disabled
    Set-ADUSer -Identity $ad_username -Enabled $false
    # Move on-prem AD to Past Employees OU
    Move-ADObject -Identity $ad_user_guid -TargetPath # GUID of Target OU
    # Verify that user is disabled
    Write-Information "On-Prem AD Status: "
    Get-ADUser $ad_username | Select-Object SamAccountName, Enabled
}
elseif ($user_location -like "There") {
    $AdminCred = Get-Credential # Domain admin  
    $ad_user_guid = Get-ADUser -Server 192.168.X.X -Credential $AdminCred -Identity $ad_username | Select-Object -ExpandProperty ObjectGUID
    Set-ADUSer -Server 192.168.X.X -Credential $AdminCred -Identity $ad_username -Enabled $false
    Move-ADObject -Server 192.168.X.X -Credential $AdminCred -Identity $ad_user_guid -TargetPath # GUID of Target OU
    Get-ADUSer -Server 192.168.X.X -Identity $ad_username | Select-Object SamAccountName, Enabled
}
elseif ($user_location -like "Everywhere") {
    $AdminCred = Get-Credential # Domain admin
    $ad_user_guid = Get-ADUser -Server 192.168.X.X -Credential $AdminCred -Identity $ad_username | Select-Object -ExpandProperty ObjectGUID
    Set-ADUSer -Server 192.168.X.X -Credential $AdminCred -Identity $ad_username -Enabled $false
    Move-ADObject -Server 192.168.X.X -Credential $AdminCred -Identity $ad_user_guid -TargetPath # GUID of Target OU
    Get-ADUser -Server 192.168.X.X -Identity $ad_username | Select-Object SamAccountName, Enabled
}

# Set AzureAD account to disabled/block sign-in, Sign AzureAD account out of all devices
Set-AzureADUser -ObjectID $azure_ad_username -AccountEnabled $false; Revoke-AzureADUserAllRefreshToken -ObjectId $azure_ad_username

Write-Information "AzureAD/Exchange Status:"
Get-AzureADUser -ObjectId $azure_ad_username | Select-Object UserPrincipalName, AccountEnabled

Write-Information "Done"

Disconnect-AzureAD