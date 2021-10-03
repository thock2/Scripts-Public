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

# Add each user listed to the group specified
ForEach ( $user in $user_name) {
    Add-DistributionGroupMember -Identity $group_name -Member $user
}

# Sign out of Exchange Online
Disconnect-ExchangeOnline