[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
    [string[]]
    $username
)

BEGIN {
    # Import Helpdesk module
    Import-Module HelpDesk
    # Connect to MSGraph, ExchangeOnline
    Connect-HelpDeskGraph
    Connect-HelpDeskExchange
    # Set GUID of Disabled Users OU
    $target_ou = ''
}

PROCESS {
    foreach ($account in $username) {
        # Try to get properties of account
        Try {
            $account_properties = (Get-ADuser -Identity $account)
        }
        Catch {
            # Exit if account cannot be found or other errors occur
            Write-Output "Unable to find an account with the name $account. Exiting."
            Exit
        }
        #Verify that account to be disabled is correct
        $confirmation = Read-Host -Prompt "Disabling $($account_properties.Name). Are you sure this matches the termination ticket? (Y/N)"
        if ($confirmation -eq "Y" -or $confirmation -eq "Yes") {
            Write-Output "Disabling $($account_properties.DisplayName)" 
            # Backup Group Memberships
            Get-GroupMemberships -username $account_properties.ObjectGUID | Out-File -FilePath "$env:LOCALAPPDATA\Temp\'$($account_properties.UserPrincipalName)'".txt
            # On-Prem properties
            # Disable account (and set manager to $null)
            Disable-ADAccount -username $account_properties
            # Remove user from all Groups
            Remove-ADGroupMembership -username $account_properties
            # Move user account to disabled users OU
            Move-ADObject -Identity $account_properties.ObjectGUID -TargetPath $target_ou
            # Azure properties
            #Disable Azure Account (Revoke Sign in)
            Disable-EntraAccount -username $account_properties.UserPrincipalName
            # Remove account from Azure groups
            Remove-AzureGroupMembership -username $account_properties.UserPrincipalName
            # Check for direct reports, remove if any exist.
            $direct_reports = Get-DirectReports -username $account_properties
            if ($direct_reports) {
                $direct_reports | ForEach-Object -Process { Remove-DirectReport -username $_ }
            }
        }
        else {
            Write-Output "Unable to verify correct account. Exiting."
            # End Script here.
            exit
        }
    }
}

END {
    # Silence annoying output
    Disconnect-Graph | Out-Null
    Disconnect-ExchangeOnline -Confirm:$false
}


