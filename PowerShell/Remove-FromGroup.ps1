[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('group')]
    [string]$group_name,

    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string[]]$user_name
)

$Credential = Get-Credential "your_domain@domain.com"
Connect-ExchangeOnline -Credential $Credential -ShowProgress $true

ForEach ( $user in $user_name) {
    $email = $user + "@domain.com"
    Remove-DistributionGroupMember -Identity $group_name -Member $email
}

Get-DistributionGroupMember -Identity $group_name | Select-Object Name, PrimarySmtpAddress

Disconnect-ExchangeOnline
