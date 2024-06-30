#
# Module manifest for module 'HelpDesk'
#
# Generated by: Terrance Hockless
#
# Generated on: 5/10/2023
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'HelpDesk.psm1'

    # Version number of this module.
    ModuleVersion     = '1.0.0'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID              = '4b0af0e5-bfbb-42f1-9e0f-6714356e55a9'

    # Author of this module
    Author            = 'Terrance Hockless'

    # Company or vendor of this module
    CompanyName       = 'tjhockless.com'

    # Copyright statement for this module
    Copyright         = '(c) thockless. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'A collection of functions used to manage AD, AzureAD, and ExchangeOnline'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules   = @("ActiveDirectory", 'microsoft.graph.authentication', 'microsoft.graph.users', 'microsoft.graph.groups', 'ExchangeOnlineManagement')

   
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @('New-User',
        'New-AzurePasswordProfile',
        'New-EntraUser',
        'New-Password',
        'New-SharedMailbox',
        'New-HelpDeskCertificate',
        'Disable-ADAccount',
        'Disable-EntraAccount'
        'Remove-Licenses',
        'Reset-Password',      
        'Convertto-SharedMailbox',
        'Add-SharedMailboxPermission',
        'Add-Licenses',
        'Remove-Licenses',
        'Remove-ADGroupMemberShip',
        'Set-MailboxForwarding',
        'Set-DirectReport',
        'Set-NewLastName',
        'Get-BitlockerRecoveryKey',
        'Get-GroupMemberships',
        'Get-StaleUsers',
        'Get-StaleComps',
        'Get-PasswordChangeDate',
        'Get-GraphToken',
        'Get-DirectReports',
        'Send-Email',
        'Connect-HelpDeskGraph',
        'Connect-HelpDeskExchange'
    )
}

