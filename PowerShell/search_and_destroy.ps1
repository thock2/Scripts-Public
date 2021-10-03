[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true,
        Mandatory = $true)]
    [Alias('blocklist')]
    [string[]]$addresses
)
# From https://docs.microsoft.com/en-us/microsoft-365/compliance/search-for-and-delete-messages-in-your-organization?view=o365-worldwide
# Modified to use sender's address instead of subject line content, and also to process multiple addresseses at a time

Import-Module ExchangeOnlineManagement

Connect-IPPSSession

foreach ($address in $addresses) {
    $search_name = $address + " " + "Removal"
    $search = New-ComplianceSearch -Name $search_name -ExchangeLocation All -ContentMatchQuery "(From:$address)"
    Start-ComplianceSearch -Identity $search.identity
    Write-Host "Waiting 5 minutes to allow the Search to complete. Please do not close this window" -ForegroundColor Green -BackgroundColor Yellow
    Start-Sleep -Seconds 300
    New-ComplianceSearchAction -SearchName $search_name -Purge -PurgeType HardDelete -Confirm:$false

}

Disconnect-ExchangeOnline -Confirm:$false