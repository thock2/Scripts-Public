[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string]$ad_username,

    [Parameter(Mandatory = $true)]
    [Alias('location')]
    [string]$ad_new_username
)

Get-ADUSer $ad_username | Rename-ADObject -NewName $ad_new_username

Get-ADUSer -Filter * | Where-Object Name -Like $ad_new_username