[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string]$ad_username
)

Unlock-ADAccount -Identity $ad_username