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

    BEGIN {}
    
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