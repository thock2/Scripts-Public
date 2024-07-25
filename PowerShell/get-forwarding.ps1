#See what accounts have forwarding enabled, and to who.
BEGIN {
    Import-Module -Name ExchangeOnlineManagement
    $session = Get-PSSession | Where-Object -Property ConfigurationName -eq "Microsoft.Exchange"
    if ($session.State -eq "Opened") {
        Write-Information "Exchange Online Session Detected, skipping connect phase"
    }
    else {
        Connect-ExchangeOnline -SkipLoadingFormatData
    }

}

PROCESS {
    Get-Mailbox | Where-Object { $_.ForwardingSMTPAddress -ne $null } | Select-Object Name, PrimarySMTPAddress, ForwardingSMTPAddress, DeliverToMailboxAndForward
}

END {}