[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('last_name')]
    [string]$given_name,

    [Parameter(Mandatory = $true)]
    [Alias('location')]
    [string]$user_location
)

$AdminCred = Get-Credential # Your admin account
Connect-AzureAD -Credential $AdminCred

if ($user_location -like "Here") {
    Get-ADUser -Filter * | Where-Object GivenName -Like "$given_name"
}
elseif ($user_location -like "There") {
    $AdminCred = Get-Credential #domain admin
    Get-ADUser -Server 192.168.X.X -Credential $AdminCred -Filter * | Where-Object GivenName -like "$given_name"
}
elseif ($user_location -like "Everywhere") {
    $AdminCred = Get-Credential #domain admin
    Get-ADUser -Server 192.168.X.X -Credential $AdminCred -Filter * | Where-Object GivenName -Like "$given_name"
}

Get-AzureADUser -SearchString $given_name | Select-Object DisplayName, UserPrincipalName