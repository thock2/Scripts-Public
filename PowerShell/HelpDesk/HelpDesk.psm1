function New-User {
    <#
.SYNOPSIS
Creates an Active Directory user (or users, depending on how many are in the document) through reading information imported from a CSV and copying the properties of a specified account.

.DESCRIPTION
This script will do the following:
1. Import the following fields from the provided CSV:
    * first_name
    * last_name
    * job_title
    * copyfrom
2. Use the provided information to create the DisplayName
3. Define a temp password for the user
4. Create the User and add them to the same groups as the copied account

.PARAMETER user_document
Provide the filepath of the CSV containing the necessary fields

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('ImportFile')]
        [string]$csv,

        [Parameter(Mandatory = $true)]
        [Alias('Domain')]
        [string]$email_domain,
    
        [Parameter()]
        [Alias('Azure')]
        [switch]$sync
    )

    BEGIN {
        Import-Module -Name ActiveDirectory
    }
    
    PROCESS {
        #Import CSV file
        $user_info = Import-Csv $csv
        #Create DisplayName Attribute
        foreach ($user in $user_info) {
            $DisplayName = $user.first_name + " " + $user.last_name # James Bond
            # Create username attribute
            $username = $user.first_name.ToLower()[0] + $user.last_name.ToLower()
            # Check if username exists - if so generate another username (jbond >> jamesb)
            if ( $null -ne $(Get-ADUSer -Filter "SamAccountName -eq '$username'")) {
                $username = $user.first_name.ToLower() + $user.last_name.ToLower()[0]
            }
            # Create e-mail address
            $email = $username + "@$($email_domain)"
            # Generate temp password
            $password = New-Password
            # Copy specified attributes of copyfrom user 
            $user_copy = Get-ADUser -Identity $user.copyfrom -Properties department, city, StreetAddress, State, Office, Manager, MemberOf
            # Deduce path of copyfrom user so that generated account can be placed in the same OU
            ##from https://community.spiceworks.com/topic/442889-copy-ad-user-with-powershell
            $path = $user_copy.DistinguishedName -replace '^cn=.+?(?<!\\),'
       
            #Define arguments for New-ADUser, create user
            $ad_argtable = @{
                "Name"                 = $DisplayName
                "GivenName"            = $user.first_name
                "DisplayName"          = $DisplayName
                "Surname"              = $user.last_name
                "SamAccountName"       = $username
                "UserPrincipalName"    = $email
                "Title"                = $user.job_title
                "AccountPassword"      = $password | ConvertTo-SecureString -Asplaintext -Force
                "EmailAddress"         = $email
                "PasswordNeverExpires" = $false
                "CannotChangePassword" = $false
                "Enabled"              = $True
                "Path"                 = $path
                "Instance"             = $user_copy
            }

            Try {
                New-ADuser @ad_argtable -ErrorAction Stop
                foreach ($group in $user_copy.MemberOf) {
                    Add-ADGroupMember -Identity $group -Members $username
                }
                Write-Output "Password for $($username) has been set to $($password)"
            }
            Catch {
                Write-Error "Unable to create $($username)"
            }
        }
        
    }

    END {}
}

function New-AzureUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('ImportFile')]
        [string]$csv
    )

    BEGIN {
        Import-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"
        Select-MgProfile -Name beta
        $userdoc = Import-CSV -Path $csv
    }

    PROCESS {

        foreach ($user in $userdoc) {
            # Create password object
            $PasswordProfile = @{
                Password = New-Password
            }
            # Create DisplayName
            $DisplayName = $user.first_name + " " + $user.last_name
            # Create Username
            $mailnickname = $user.first_name.ToLower()[0] + $user.last_name.ToLower()
            # Properties table
            $argtable = @{
                "DisplayName"       = $DisplayName
                "PasswordProfile"   = $PasswordProfile
                "UserPrincipalName" = $user.email
                "AccountEnabled"    = $true
                "JobTitle"          = $user.job_title
                "Department"        = $user.department
                "GivenName"         = $user.last_name
                "Surname"           = $user.first_name
                "MailNickName"      = $mailnickname
                "UsageLocation"     = 'US'
            }
            try {
                New-MgUser @argtable
            }
            catch {
                Write-Output "Unable to create $($DisplayName)"
            }
        }
    }

    END {}
}
function Disable-ADAccount {
    <#
    .SYNOPSIS
    Disables a specified Active Directory User

    .DESCRIPTION
    This script will do the following:
    1. Read the username provided to the username parameter
    2. Disable the user
    3. Set the manager property to null

    .PARAMETER username
    Provide the username of the user you would like to disable

    .EXAMPLE
    Disable-ADAccount -username mjackson
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $username
    )
    Set-ADUser -Identity $username -Enabled $false -Manager $null
}
function Get-GroupMemberships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $username
    )

    Begin {
        Import-Module -Name ActiveDirectory
    }

    Process {
        Get-ADPrincipalGroupMembership -Identity $username | Select-Object -Property Name, DistinguishedName, GroupCategory | Sort-Object -Property GroupCategory
    }

    End {}
}

function Remove-ADGroupMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [String][Microsoft.ActiveDirectory.Management.ADUser]
        $username
    )

    BEGIN {}

    PROCESS {
        $groups = Get-ADUSer -Identity $username -Properties memberOf | Select-Object -ExpandProperty memberOf
        foreach ($group in $groups) {
            Remove-ADGroupMember -Identity $group -Members $username -Confirm:$false
        }
    }
    END {}
}
function Disable-AzureAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]
        $username
    )

    BEGIN {
        Import-Module -Name Microsoft.Graph.Authentication
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All"
        Select-MgProfile -Name beta
    }

    PROCESS {
        foreach ($user in $username) {
            $uri_01 = "https://graph.microsoft.com/beta/users/$user/InvalidateAllRefreshTokens"
            Invoke-GraphRequest -Method POST -Uri $uri_01
            $body = @"
    {
        "accountEnabled": false
    }
    {
        "showInAddressList": false
    }
"@
            $uri_02 = "https://graph.microsoft.com/beta/users/$user" 
            Invoke-GraphRequest -Method Patch -Uri $uri_02 -Body $body -ContentType application/json
        }
    }
    END {}
}
function Remove-AzureGroupMembership {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]
        $username
    )
    BEGIN {
        Import-Module -Name Microsoft.Graph.Authentication
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All"
        Select-MgProfile -name beta
    }

    PROCESS {
        foreach ($user in $username) {
            #get user id
            $user_uri = "https://graph.microsoft.com/beta/users/$user"
            $user_request = Invoke-GraphRequest -Method Get -Uri $user_uri -ContentType application/json
            #get group membership
            $group_uri = "https://graph.microsoft.com/beta/users/$user/memberOf"
            $groups = Invoke-GraphRequest -Method Get -Uri $group_uri -ContentType application/json
            $ref = '$ref'
            #for each group id in group collection, issue delete request to remove user from that group
            foreach ($group in $groups.value) {
                if ($group.GroupTypes -eq "DynamicMembership" -or $group.OnPremisesSyncEnabled -eq $true -or $group.MailEnabled -eq $true) {
                    Write-Information "Group Membership cannot be changed. Skipping $($group.DisplayName)."
                }
                else {
                    $remove_uri = "https://graph.microsoft.com/beta/groups/$($group.id)/members/$($user_request.id)/$ref"
                    Invoke-GraphRequest -Method DELETE -uri $remove_uri
                }
            }
        }
    }
    END {}

}

function Add-Licenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $email_address,

        [Parameter()]
        [switch]
        $E3,

        [Parameter()]
        [switch]
        $365Essentials,

        [Parameter()]
        [switch]
        $BCTeamMember
    )

    Begin {
        Import-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement
        Connect-MgGraph -Scopes "User.ReadWrite.All, Organization.Read.All"
        Select-MgProfile -Name beta
    }

    Process {

        foreach ($user in $email_address) {
            #Define UserID
            $userID = (Get-MgUser -Filter "mail eq '$user'").Id
            # Set Usage Location
            Update-MGUser -UserId $userID -UsageLocation US
            #Assign E3
            if ($E3) {
                #Define SkuID
                $E3SKU = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPACK" }

                #Assign License, If none available, throw error
                Try {
                    Set-MgUserLicense -UserId $userID -AddLicenses @{SkuID = $E3SKU.SkuId } -RemoveLicenses @() -ErrorAction Stop
                }
                Catch {
                    Write-Information "No Remaining Licenses available for $($E3SKU.SkuPartNumber)" -InformationAction Continue
                }
            }
            #Assign M365 Business Essentials
            if ($365Essentials) {
                $essential_sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq "O365_BUSINESS_ESSENTIALS" }

                Try {
                    Set-MgUserLicense -UserId $userID -AddLicenses @{SkuID = $essential_sku.SkuId } -RemoveLicenses @() -ErrorAction Stop
                }
                Catch {
                    Write-Information "No Remaining Licenses available for $($essential_sku.SkuPartNumber)" -InformationAction Continue
                }
            }
            # Assign NAV BC Team Member
            if ($BCTeamMember) {
                $bc_team_sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq "DYN365_BUSCENTRAL_TEAM_MEMBER" }

                Try {
                    Set-MgUserLicense -UserId $userID -AddLicenses @{SkuID = $bc_team_sku.SkuId } -RemoveLicenses @() -ErrorAction Stop
                }
                Catch {
                    Write-Information "No Remaining Licenses available for $($bc_team_sku.SkuPartNumber)" -InformationAction Continue
                }
            }
        }

    }
    End {
        #Get-MgUserLicenseDetail -UserId $userID
    }
}
function Remove-Licenses {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $username
    )

    Begin {
        Import-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users.Actions
        Connect-MgGraph -Scopes "User.ReadWrite.All, Organization.Read.All"
        Select-MgProfile -Name beta
    }

    Process {
        foreach ($license in $skuID) {
            $user_uri = "https://graph.microsoft.com/beta/users/$username"
            $user_request = Invoke-GraphRequest -Method GET -Uri $user_uri -ContentType application/json
            [Array]$skuID = $user_request.assignedLicenses.SkuID
            Set-MgUserLicense -UserId $username -RemoveLicenses $license -AddLicenses @()
        }
    }
    End {}
}
# Generate Password
## Adapted From https://stackoverflow.com/questions/37256154/powershell-password-generator-how-to-always-include-number-in-string
function New-Password {
    $MinimumPasswordLength = 12
    $MaximumPasswordLength = 16
    $PasswordLength = Get-Random -InputObject ($MinimumPasswordLength..$MaximumPasswordLength)
    $AllowedPasswordCharacters = [char[]]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?@#$%^&'
    $Regex = "(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)"

    do {
        $Password = ([string]($AllowedPasswordCharacters |
                Get-Random -Count $PasswordLength) -replace ' ')
    }    until ($Password -cmatch $Regex)

    $Password
}
function Reset-Password {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $user
    )

    BEGIN {
        Import-Module ActiveDirectory
    }

    PROCESS {
        $password = New-Password
        Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -Asplaintext $password -Force)
        Write-Output "Password for $user reset to $password"
    }
    END {}
}
function Get-StaleUsers {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]
        $lastlogindate
    )

    Begin {
        Import-Module -Name ActiveDirectory
    }

    Process {
        Write-Output "The following Users Have not logged in within the last $($lastlogindate) Days: "
        Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate | Where-Object { $_.LastLogonDate -le (Get-Date).AddDays(-$lastlogindate) } | `
            Select-Object Name, LastLogonDate, DistinguishedName | Sort-Object LastLogonDate
    }

    END {}
}
function Get-StaleComps {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]
        $lastlogindate
    )

    Begin {
        Import-Module ActiveDirectory
    }

    Process {
        Write-Output "The following Computers Have not logged in within the last $($lastlogindate) Days: "
        Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate | Where-Object { $_.LastLogonDate -le (Get-Date).AddDays(-$lastlogindate) } | `
            Select-Object Name, LastLogonDate, DistinguishedName | Sort-Object LastLogonDate
    }

    END {}
}
function New-SharedMailbox {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $mailboxaddress,
        [Parameter(Mandatory = $true)]
        [String]
        $DisplayName
    )

    Begin {
        Import-Module -Name ExchangeOnlineManagement
        $session = Get-PSSession | Where-Object -Property ConfigurationName -eq "Microsoft.Exchange"
        if ($session.State -eq "Opened") {
            Write-Information "Exchange Online Session Detected, skipping connect phase"
        }
        else {
            Connect-ExchangeOnline
        }
    }

    Process {
        New-Mailbox -Name $mailboxaddress -DisplayName $DisplayName -PrimarySmtpAddress $mailboxaddress -Shared
    }

    End {}
}
function Convertto-SharedMailbox {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $UserPrincipalName
    )

    Begin {
        Import-Module ExchangeOnlineManagement
        $session = Get-PSSession | Where-Object -Property ConfigurationName -eq "Microsoft.Exchange"
        if ($session.State -eq "Opened") {
            Write-Information "Exchange Online Session Detected, skipping connect phase"
        }
        else {
            Connect-ExchangeOnline
        }
    }

    Process {
        $UserPrincipalName | ForEach-Object -Process { Set-Mailbox -Identity $_ -Type Shared }
    }

    End {}
}
function Add-SharedMailboxPermission {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $MailboxAddress,

        [Parameter(Mandatory = $true)]
        [string[]]
        $RecipientAddress,

        [Parameter()]
        [Alias('FullAccess')]
        [switch]$fullaccess_permission,


        [Parameter()]
        [Alias('SendAs')]
        [switch]$send_permission,

        [Parameter()]
        [Alias('SendOnBehalf')]
        [switch]$send_on_behalf_permission
    )

    BEGIN {
        Import-Module -Name ExchangeOnlineManagement
        $session = Get-PSSession | Where-Object -Property ConfigurationName -eq "Microsoft.Exchange"
        if ($session.State -eq "Opened") {
            Write-Information "Exchange Online Session Detected, skipping connect phase"
        }
        else {
            Connect-ExchangeOnline
        }
    }

    Process {
        if ($fullaccess_permission) {
            $RecipientAddress | ForEach-Object {
                Add-MailboxPermission -Identity $MailboxAddress -User $_ -AccessRights FullAccess -InheritanceType All
            }
        }

        if ($send_permission) {
            $RecipientAddress | ForEach-Object {
                Add-RecipientPermission -Identity $MailboxAddress -Trustee $_ -AccessRights SendAs -Confirm:$false
            }
        }
        
        if ($send_on_behalf_permission) {
            $RecipientAddress | ForEach-Object {
                Set-Mailbox -Identity $MailboxAddress -GrantSendOnBehalfTo @{Add = "$_" }
            }
        }
    }

    End {}
}
function Set-MailboxForwarding {
    [CmdletBinding()]
    param (
        # Target Address
        [Parameter()]
        [String]
        $email_address,
        # Recipient Address
        [Parameter(Mandatory = $true)]
        [String]
        $recipient_address
    ) 

    Begin {
        Import-Module -Name ExchangeOnlineManagement
        $session = Get-PSSession | Where-Object -Property ConfigurationName -eq "Microsoft.Exchange"
        if ($session.State -eq "Opened") {
            Write-Information "Exchange Online Session Detected, skipping connect phase"
        }
        else {
            Connect-ExchangeOnline
        }
    }

    Process {
        Set-Mailbox -Identity $email_address -DeliverToMailboxAndForward $true -ForwardingSMTPAddress $recipient_address
    }

    End {}
    
}

function Get-BitlockerRecoveryKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.ActiveDirectory.Management.ADComputer]
        $ComputerName
    ) 

    BEGIN {
        Import-Module -Name ActiveDirectory
    }

    Process {
        $computer = Get-ADComputer -Identity $ComputerName
        $bitlocker_key = Get-ADObject -Filter { ObjectClass -eq 'msFVE-RecoveryInformation' } -SearchBase $computer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
        $results = New-Object -TypeName psobject -Property @{'ComputerName' = $computer.name; 'Recovery Key' = $bitlocker_key.'msFVE-RecoveryPassword' }
    }
    End {
        $results
    }
}