<#
.SYNOPSIS
Disables a users local AD account, AzureAD account, and removes them from any onprem/online groups they are a member of.
.DESCRIPTION
Requires the AzureAD Powershell Module
This script will do the following:
1. Check for the AzureAD Powershell Module. If not available it will be installed
2. Remove the specified user account from all local and online groups
3  Disable the on-prem account and move to the "Deprovision" OU
4. Disable the online account, block sign in of the online account, and Delete the account if specified.
.PARAMETER ad_username
Provide the users' ad username (kwest).
.PARAMETER delete
Delete AzureAD user account, if "y", delete, if "n", keep (but still will be blocked from sign in and disabled)
.EXAMPLE
ah-disable_user.ps1 -ad_username <username> -delete <y/n>
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string[]]$ad_username,

    [Parameter(Mandatory = $False)]
    [Alias('delete(y/n)')]
    [string]$delete
)
Import-Module ActiveDirectory
Connect-AzureAD
#Connect-ExchangeOnline
$target_ou = '' # The ObjectGUID of the OU you want to move to, use: Get-ADOrganizationUnit -Filter {Name -like "<Name of OU>"}
foreach ($user in $ad_username) {
    $ad_user = Get-ADUser -Identity $ad_username #GetUserProperties
    $ad_groups = Get-ADPrincipalGroupMembership -Identity $ad_user | Where-Object Name -NotMatch 'Domain Users'     #Pull a list of the users local group memberships
    $azure_user = Get-AzureADUser -ObjectID (Get-ADUSer $ad_username | Select-Object -ExpandProperty UserPrincipalName)   #define User Email
    $azure_groups = Get-AzureADUSerMembership -ObjectID $azure_user.objectid #Pull a list of the users azure group memberships

    #Remove User from all local/synced Groups
    foreach ($ad_group in $ad_groups) {
        Remove-ADGroupMember -Identity $ad_group.objectGUID -Members $ad_username -Confirm:$False
    }
    Set-ADUser -Identity $ad_username -Enabled $false     # Disable User
    Move-ADObject -Identity $ad_user.objectGUID -TargetPath $target_ou # Move AD account to deprovision OU

    #Remove User from all azure Groups
    foreach ($azure_group in $azure_groups) {
        if ($azure_group.DirSyncEnabled -eq "True") {
            Write-Warning -Message "On-Prem object. Skipping."
        }
        else {
            Remove-AzureADGroupMember -ObjectID $azure_group.objectid -MemberID $azure_user.objectid   
        }
    }
    Set-AzureADUser -ObjectId $azure_user.objectid -AccountEnabled $false; Revoke-AzureADUserAllRefreshToken -ObjectId $azure_user.objectid     # Disable AzureAD Account, Revoke all Siginins
    if ($delete -eq "y") {
        Remove-AzureADUser -ObjectID $azure_user.objectid
    }
    else {
        break
    }
}
Invoke-Command -ComputerName (Read-Host "Input Name of Server hosting AzureAD Sync") -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }
Disconnect-AzureAD