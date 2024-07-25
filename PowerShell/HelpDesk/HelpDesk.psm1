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
function New-AzurePasswordProfile {
    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
    $PasswordProfile.Password = New-Password -passphrase
    $PasswordProfile.EnforceChangePasswordPolicy = $true
    $PasswordProfile.ForceChangePasswordNextLogin = $true

    return $PasswordProfile
}
function New-EntraUser {
    <#
.SYNOPSIS
Creates an Entra user (or users, depending on how many are in the document) through reading information imported from a CSV.
.DESCRIPTION
This script will do the following:
1. Import the following fields from the provided CSV:
    * first_name
    * last_name
    * job_title
    * email
    * Department
2. Use the provided information to create the DisplayName
3. Define the temp password for the user
.PARAMETER user_document
Provide the filepath of the CSV containing the necessary fields
.EXAMPLE
New-EntraUser -ImportFile file.csv -temp_password 'hunter2'
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('ImportFile')]
        [string]$csv
    )

    BEGIN {
        # Import required modules
        Import-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users
        # Connect to MS Grpah
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"
        # Import CSV containing user information
        $userdoc = Import-CSV -Path $csv
    }

    PROCESS {

        foreach ($user in $userdoc) {
            # Create DisplayName
            $DisplayName = $user.first_name + " " + $user.last_name
            # Create Username
            $mailnickname = $user.first_name.ToLower()[0] + $user.last_name.ToLower()
            # Properties table
            $argtable = @{
                "DisplayName"       = $DisplayName
                "PasswordProfile"   = New-AzurePasswordProfile
                "UserPrincipalName" = $user.email
                "AccountEnabled"    = $true
                "JobTitle"          = $user.job_title
                "Department"        = $user.department
                "GivenName"         = $user.last_name
                "Surname"           = $user.first_name
                "MailNickName"      = $mailnickname
                "UsageLocation"     = 'US'
            }
            New-MgUser @argtable
        }
    }

    END {}
}
function New-Password {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'Password')]
        [switch]
        $standard_pass,

        [Parameter(ParameterSetName = 'PassPhrase')]
        [switch]
        $passphrase,

        [Parameter(ParameterSetName = 'PassPhrase')]
        [System.IO.FileInfo]
        $word_list = 'C:\Program Files\WindowsPowerShell\Modules\HelpDesk\Extras\1000-most-common-words.txt'
        #$word_list = ".\1000-most-common-words.txt"
    )
    if ($standard_pass) {
        $MinimumPasswordLength = 12
        $MaximumPasswordLength = 16
        $PasswordLength = Get-Random -InputObject ($MinimumPasswordLength..$MaximumPasswordLength)
        $AllowedPasswordCharacters = [char[]]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?@#$%^&'
        $Regex = "(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)"

        do {
            $Password = ([string]($AllowedPasswordCharacters |
                    Get-Random -Count $PasswordLength) -replace ' ')
        }    until ($Password -cmatch $Regex)
    }
    if ($passphrase) {
        $dictionary = Get-Content $word_list
        $special_chars = [char[]]"!?@#$%^&"
        $numbers = [char[]]"0123456789"
        $first_word = (Get-Random -InputObject $dictionary)
        $first_word = $first_word.Substring(0, 1).ToUpper() + $first_word.Substring(1).ToLower()
        $Password = $first_word + "-" + (Get-Random -InputObject $dictionary) + "-" + (Get-Random -InputObject $dictionary) + "-" + (Get-Random -InputObject $dictionary) + ($special_chars | Get-Random) + ($numbers | Get-Random)
    }
    $Password
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
        Connect-HelpDeskExchange
    }

    Process {
        New-Mailbox -Name $mailboxaddress -DisplayName $DisplayName -PrimarySmtpAddress $mailboxaddress -Shared
    }

    End {}
}
function New-HelpDeskCertificate {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $DNSName = $env:COMPUTERNAME + "." + (Get-DnsClient).ConnectionSpecificSuffix[0],
        
        [Parameter()]
        [String]
        $FriendlyName = $env:COMPUTERNAME,

        [Parameter()]
        [string]
        $CertStore = 'Cert:\CurrentUser\My',

        [Parameter()]
        [string]
        $ExportPath = "$env:LOCALAPPDATA\Temp",

        [Parameter()]
        [switch]
        $Exchange
    )
    $CertParam = @{
        'KeyAlgorithm'      = 'RSA'
        'KeyLength'         = 2048
        'KeyExportPolicy'   = 'NonExportable'
        'DnsName'           = $DNSName
        'FriendlyName'      = $FriendlyName
        'CertStoreLocation' = $CertStore
        'NotAfter'          = (Get-Date).AddYears(1)
    }
    if ($Exchange) {
        $CertParam = @{
            'DnsName'           = $DNSName
            'CertStoreLocation' = $CertStore
            'NotAfter'          = (Get-Date).AddYears(1)
            'KeySpec'           = 'KeyExchange'
        }
        $Cert = New-SelfSignedCertificate @CertParam
    }
    else {
        $Cert = New-SelfSignedCertificate @CertParam
    }
    Write-Output "The Thumbprint of this Certificate is: `n$($cert.thumbprint)`n"
    Write-Output "This certificate will be exported to: `n $ExportPath"
    Export-Certificate -Cert $Cert -FilePath $ExportPath\$DNSName.cer
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
function Disable-EntraAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]
        $username
    )

    BEGIN {
        Connect-HelpDeskGraph
    }

    PROCESS {
        foreach ($user in $username) {
            $uri_01 = "https://graph.microsoft.com/beta/users/$user/InvalidateAllRefreshTokens"
            Invoke-GraphRequest -Method POST -Uri $uri_01
            $body = @"
    {
        "accountEnabled": false
    }
"@
            $uri_02 = "https://graph.microsoft.com/beta/users/$user" 
            Invoke-GraphRequest -Method Patch -Uri $uri_02 -Body $body -ContentType application/json
        }
    }
    END {}
}
function Remove-Licenses {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]]
        $username
    )

    foreach ($user in $username) {
        $user_uri = "https://graph.microsoft.com/beta/users/$user"
        $user_request = Invoke-GraphRequest -Method GET -Uri $user_uri -ContentType application/json
        [Array]$skuID = $user_request.assignedLicenses.SkuID

        foreach ($license in $skuID) {
            Set-MgUserLicense -UserId $user -RemoveLicenses $license -AddLicenses @()        
        }
    }
}
function Reset-Password {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $user
    )

    BEGIN {}

    PROCESS {
        $password = New-Password
        Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -Asplaintext $password -Force)
        Write-Output "Password for $user reset to $password"
    }
    END {}
}
function Convertto-SharedMailbox {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $UserPrincipalName
    )

    Begin {
        Connect-HelpDeskExchange
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
        Connect-HelpDeskExchange
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

    Begin {}

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
                    Write-Error $error[0].ErrorDetails
                }
            }
            #Assign M365 Business Essentials
            if ($365Essentials) {
                $essential_sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq "O365_BUSINESS_ESSENTIALS" }

                Try {
                    Set-MgUserLicense -UserId $userID -AddLicenses @{SkuID = $essential_sku.SkuId } -RemoveLicenses @() -ErrorAction Stop
                }
                Catch {
                    Write-Error $error[0].ErrorDetails
                }
            }
            # Assign NAV BC Team Member
            if ($BCTeamMember) {
                $bc_team_sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq "DYN365_BUSCENTRAL_TEAM_MEMBER" }

                Try {
                    Set-MgUserLicense -UserId $userID -AddLicenses @{SkuID = $bc_team_sku.SkuId } -RemoveLicenses @() -ErrorAction Stop
                }
                Catch {
                    Write-Error $error[0].ErrorDetails
                }
            }
        }

    }
    End {}
}
function Remove-Licenses {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]]
        $username
    )

    foreach ($user in $username) {
        $user_uri = "https://graph.microsoft.com/beta/users/$user"
        $user_request = Invoke-GraphRequest -Method GET -Uri $user_uri -ContentType application/json
        [Array]$skuID = $user_request.assignedLicenses.SkuID

        foreach ($license in $skuID) {
            Set-MgUserLicense -UserId $user -RemoveLicenses $license -AddLicenses @()        
        }
    }
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
        Connect-HelpDeskExchange
    }

    Process {
        Set-Mailbox -Identity $email_address -DeliverToMailboxAndForward $true -ForwardingSMTPAddress $recipient_address
    }

    End {}
    
}
function Set-DirectReport {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $username,

        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $manager
    )
    # Set direct report (manager) to specified user
    Set-ADuser -Identity $username -Manager $manager
}
function Set-NewLastName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $username,

        [Parameter(Mandatory = $true)]
        [String]
        $new_last_name,

        [Parameter()]
        [switch]
        $update_lastname,

        [Parameter()]
        [switch]
        $update_emailaddress
    )

    BEGIN {
        # Grab user properties
        $user_properties = Get-ADuser -Identity $username -Properties ProxyAddresses, EmailAddress
        # Create Surname
        $new_last_name_format = $new_last_name.SubString(0, 1).ToUpper() + $new_last_name.Substring(1, $new_last_name.Length - 1)
        # Create Full Name
        $new_fullname = $user_properties.GivenName + " " + $new_last_name_format
        # Create new SamAccountName
        $new_username = $user_properties.GivenName.ToLower()[0] + $new_last_name.ToLower()
        # Create UserPrincipalName / email address
        $new_email = $new_username + "@arteriorshome.com"
        # Get old e-mail address
        $old_email = $user_properties.EmailAddress
    }

    PROCESS {
        if ($update_lastname) {
            # Update just last name
            Try {
                Set-ADUser -Identity $username -Surname $new_last_name_format -DisplayName $new_fullname
                $new_user_properties = Get-ADUser -Identity $username
                Write-Output "We have updated the following properties for $($user_properties.SamAccountName):
                    `nSurname has been changed from $($user_properties.Surname) to $($new_user_properties.Surname)"
            }
            catch {
                Write-Error $error[0].ErrorDetails -ErrorAction Stop
            }
        }
        if ($update_emailaddress) {
            #Update UPN, SamAccountName, Email Address, ProxyAddresses
            $property_updates = @{
                'UserPrincipalName' = $new_email
                'EmailAddress'      = $new_email
                'SamAccountName'    = $new_username
                'Add'               = @{
                    ProxyAddresses = "smtp:$old_email,SMTP:$new_email" -split "," 
                }
            }
            # Set Properties
            try {
                Set-ADUser -Identity $username @property_updates
                $new_user_properties = Get-ADUser -Identity $new_username -Properties ProxyAddresses, EmailAddress
                Write-Output "We have updated the following properties for $($user_properties.SamAccountName): 
                    `nUserPrincipalName/E-Mail Address has been changed from $($user_properties.UserPrincipalName) to $($new_user_properties.UserPrincipalName)
                    `nSamAccountName has been changed from $($user_properties.SamAccountName) to $($new_user_properties.SamAccountName)
                    `nProxy Addresses have been added to preserve the previous E-mail address. Those are: `n$($property_updates.Add.Values)"
            }
            catch {
                Write-Error $error[0].ErrorDetails -ErrorAction Stop
            }
        }
    }

    END {}
    
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
        $bitlocker_key = Get-ADObject -Filter { ObjectClass -eq 'msFVE-RecoveryInformation' } -SearchBase (Get-ADComputer -Identity $ComputerName).DistinguishedName -Properties 'msFVE-RecoveryPassword'
        $results = New-Object -TypeName psobject -Property @{'ComputerName' = (Get-ADComputer -Identity $ComputerName).Name; 'Recovery Key' = $bitlocker_key.'msFVE-RecoveryPassword' }
    }
    End {
        return $results
    }
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
function Get-PasswordChangeDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $username
    )
    Get-ADUser -Identity $username -Properties PasswordLastSet, PasswordExpired | Select-Object Name, SamAccountName, PasswordLastSet, PasswordExpired
}
function Get-GraphToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $client_secret,

        [Parameter()]
        [string]
        $tenant_ID = "" ,

        [Parameter()]
        [string]
        $client_ID = ""
    )

    $tokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $client_ID
        Client_Secret = $client_secret
    }
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenant_ID/oauth2/v2.0/token" -Method POST -Body $tokenBody
    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }
    return $headers
}
function Get-DirectReports {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $username
    )
    # Get direct reports
    $direct_reports = Get-ADuser -Filter "Manager -eq '$username'"
    # return direct reports to specified user
    if ($null -eq $direct_reports) {
        Write-Information "No Direct Reports found under $username"
    }
    else {
        return $direct_reports
    }
}
function Send-Email {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $sender_address,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $auth_headers,

        [Parameter(Mandatory = $true )]
        [string]
        $recipient_address,

        [Parameter()]
        [string]
        $message_subject = "",

        [Parameter()]
        [string]
        $message_body = "",

        [Parameter()]
        [System.IO.FileInfo]
        $attachment = ""
    )
    BEGIN {
        $attachment_info = Get-ChildItem -Path $attachment
        $base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($attachment_info.VersionInfo.FileName))
    }

    PROCESS {
        $sender_uri = "https://graph.microsoft.com/v1.0/users/$sender_address/sendMail"
        $body_json_attach = @"
    {
        "message": {
          "subject": "$message_subject",
          "body": {
            "contentType": "HTML",
            "content": "$message_body"
          },
          
          "toRecipients": [
            {
              "emailAddress": {
                "address": "$recipient_address"
              }
            }
          ]
          ,"attachments": [
            {
              "@odata.type": "#microsoft.graph.fileAttachment",
              "name": "$($attachment_info.Name)",
              "contentType": "text/plain",
              "contentBytes": "$base64string"
            }
          ]
        },
        "saveToSentItems": "false"
      }
"@
    }
    END {
        #Get-GraphToken -tenantID -clientID -client_secret
        # Send E-mail
        Invoke-RestMethod -Method POST -Uri $sender_uri -Headers $auth_headers -Body $body_json_attach
    }
}
function Remove-AzureGroupMembership {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]
        $username
    )
    BEGIN {
        Connect-HelpDeskGraph
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
function Connect-HelpDeskGraph {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $appID = $graph_app_id,

        [Parameter()]
        [string]
        $TenantID = $tenant_id,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate = $graph_thumbprint
    )
    $session = Get-MgContext
    if ($null -eq $session) {
        Write-Information "No existing Graph connection found. Connecting now" -InformationAction Continue
        Connect-MgGraph -TenantId $TenantID -AppID $appID -Certificate $Certificate -NoWelcome -Verbose
    }
    elseif ( $session.TenantId -eq $TenantID) {
        Write-Information "Active Graph connection found. No further action needed." -InformationAction Continue
    }
}
function Connect-HelpDeskExchange {  
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $appID = $exchange_app_id,

        [Parameter()]
        [string]
        $organization = 'arteriorshome.com',

        [Parameter()]
        [string]
        $thumbprint = $exchange_thumbprint
    )
    
    # Check for existing connection
    $session = Get-ConnectionInformation
    if ($null -eq $session) {
        Write-Information "No existing Exchange Online Connections found, Connecting now" -InformationAction Continue
        Connect-ExchangeOnline -CertificateThumbPrint $thumbprint -AppID $appID -Organization $organization -ShowBanner:$false -ShowProgress $false -SkipLoadingFormatData
    }
    elseif ($session.TokenStatus -eq "Active") {
        Write-Information "Active Exchange Online Session Found. No further action needed." -InformationAction Continue
    }
}