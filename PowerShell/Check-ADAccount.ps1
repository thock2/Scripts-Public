[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('last_name')]
    [string]$surname)

Connect-AzureAD -Credential $AdminCred
Get-ADuser -Filter { Surname -Like $surname }
