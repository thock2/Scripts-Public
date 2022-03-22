<#
.SYNOPSIS
Creates an Active Directory user (or users, depending on how many are in the document) through reading information imported from a CSV and copying the properties of a specified account.
.DESCRIPTION
This script will do the following:
1. Import the following fields from the provided CSV:
    * first_name
    * last_name
    * job_title
    * username
    * email
2. Use the provided information to create the DisplayName
3. Define the temp password for the user
4. Create the User
5. If specified, use Invoke-Command to specify the host server on-prem and execute a Delta Sync
.PARAMETER user_document
Provide the filepath of the CSV containing the necessary fields
.PARAMETER sync
If included in command, invoke a forced AzureAD sync to the specified machine
.EXAMPLE
ad-newuser.ps1 -user_document $env:USERPROFILE/userdoc.csv
.EXAMPLE
ad-newuser.ps1 -user_document $env:USERPROFILE/userdoc.csv -sync
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('CSV')]
    [string[]]$user_document,
    [Parameter(Mandatory = $false)]
    [Alias('ADSync')]
    [switch]$sync
)

Import-Module ActiveDirectory
$user_info = Import-Csv $user_document

foreach ($user in $user_info) {
    $DisplayName = $user.first_name + " " + $user.last_name
    $password = ConvertTo-SecureString -AsPlainText 'temp_password_here' -Force
    #Define arguments for New-ADUser, create user
    $ad_argtable = @{
        "Name"                  = $DisplayName
        "GivenName"             = $user.first_name
        "DisplayName"           = $DisplayName
        "Surname"               = $user.last_name
        "SamAccountName"        = $user.username
        "UserPrincipalName"     = $user.email
        "Title"                 = $user.job_title
        "AccountPassword"       = $password
        "email"                 = $user.email
        "OfficePhone"           = '123.456.7890'
        "PasswordNeverExpires"  = $false
        "CannotChangePassword"  = $false
        "Enabled"               = $True
        "ChangePasswordAtLogon" = $True
    }

    New-ADUser @ad_argtable
}
# AD Sync
if ($sync) {
    Invoke-Command -ComputerName (Read-Host -Prompt "Input FQDN of Server hosting AD Sync") -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }
}