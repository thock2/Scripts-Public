# Search for a phishing message in all mailboxes and remove what is found.
# From https://docs.microsoft.com/en-us/microsoft-365/compliance/search-for-and-delete-messages-in-your-organization?view=o365-worldwide
# Modified to use sender's address instead of subject line content

#Install-Module -Name ExchangeOnlineManagement
#Import-Module ExchangeOnlineManagement

$credential = Get-credential 'admin@yourdomain.onmicrosoft.com'

Connect-IPPSSession -credential $credential
$search_name = Read-Host "Name of search?"
$sender_address = Read-Host "Sender address?"

$Search = New-ComplianceSearch -Name $search_name -ExchangeLocation All -ContentMatchQuery "(From:$sender_address)"
Start-ComplianceSearch -Identity $Search.Identity

Write-Host "Waiting 5 minutes to allow the Search to complete. Please do not close this window" -ForegroundColor Green -BackgroundColor Yellow
Start-Sleep -Seconds 300

$purge_name = $search_name + "_Purge"
New-ComplianceSearchAction -SearchName $purge_name -Purge -PurgeType HardDelete

#Show Progress of Search/Delete Action
Get-ComplianceSearchAction -Identity $purge_name -Details

Disconnect-ExchangeOnline -Confirm:$false
