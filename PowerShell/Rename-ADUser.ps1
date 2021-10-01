[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string]$ad_username,

    [Parameter(Mandatory = $true)]
    [Alias('location')]
    [string]$ad_new_username
)

Rename-ADObject -identity (Get-ADUSer $ad_username).ObjectGUID -NewName $ad_new_username