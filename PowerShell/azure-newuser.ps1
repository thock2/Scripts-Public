<#
.SYNOPSIS
Creates an Azure Active Directory user (or users, depending on how many are in the document) through reading information imported from a CSV.
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
azure-newuser.ps1 -user_document file.csv -temp_password 'hunter2'
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('CSV')]
    [string]$user_document
)
#permissions needed to make new user?
Connect-MgGraph -Scopes

#how are we creating the password?
function azure_password {
    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
    $PasswordProfile.Password = $Password
    $PasswordProfile.EnforceChangePasswordPolicy = $true
    $PasswordProfile.ForceChangePasswordNextLogin = $true
}

function add-users ($csv) {
    $import = Import-Csv -Path $csv
    foreach ($user in $import) {
        $DisplayName = $user.first_name + " " + $user.last_name
        $argtable = @{
            "DisplayName"       = $DisplayName 
            "PasswordProfile"   = azure_password
            "UserPrincipalName" = $user.email
            "AccountEnabled"    = $true 
            "JobTitle"          = $user.job_title
            "Department"        = $user.department
            "GivenName"         = $user.last_name
            "Surname"           = $user.first_name
            "UsageLocation"     = 'US'
        }
        New-MgUser @argtable
    }
}

add-users -csv $user_document

Disconnect-MgGraph