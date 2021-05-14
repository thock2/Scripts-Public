[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('group')]
    [string]$group_name,

    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string[]]$user_name
)

# Sign in to Exchange Online
$Credential = Get-Credential #Username of admin account
Connect-ExchangeOnline -Credential $Credential

# Add each user listed to the group specified
ForEach ( $user in $user_name) {
    $email = $user + "@yourdomain.com"
    Add-DistributionGroupMember -Identity $group_name -Member $email
}

# Get list of users in group to show that change has been made
Get-DistributionGroupMember -Identity $group_name | Select-Object Name, PrimarySmtpAddress

# Sign out of Exchange Online
Disconnect-ExchangeOnline