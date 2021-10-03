[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('group')]
    [string]$group_name,

    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string[]]$user_name
)

Connect-ExchangeOnline 
foreach ( $user in $user_name ) {
    Remove-DistributionGroupMember -Identity $group_name -Member $user_name
}

Disconnect-ExchangeOnline -Confirm:$false