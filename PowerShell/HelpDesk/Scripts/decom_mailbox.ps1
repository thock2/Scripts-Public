[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $email_address,

    [Parameter()]
    [switch]
    $forwarding
)

BEGIN {
    Connect-HelpDeskGraph
    Connect-HelpDeskExchange
}

PROCESS {
    foreach ($email in $email_address) {
        # Convert account to shared mailbox
        Convertto-SharedMailbox -UserPrincipalName $email
        # Remove Calendar Items to free any rooms that were reserved
        Remove-CalendarEvents -Identity $email -CancelOrganizedMeetings -QueryWindowInDays 365 -Confirm:$false
        # Apply forwarding if specified
        if ($forwarding) {
            $forward_address = Read-Host -Prompt "Please type the e-mail address to forward this inbox to.`n Press 'Enter' when finished."
            Set-MailboxForwarding -email_address $email -recipient_address $forward_address
        }
        Remove-Licenses -username $email
    }
}

END {
    Disconnect-Graph | Out-Null
    Disconnect-ExchangeOnline -Confirm:$false
}