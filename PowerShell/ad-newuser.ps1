<#
.SYNOPSIS
Creates an Active Directory user (or users, depending on how many are in the document) through reading information imported from a CSV.
.DESCRIPTION
This script will do the following:
1. Import the following fields from the provided CSV:
    * first_name
    * last_name
    * job_title
    * email
2. Use the provided information to create the DisplayName
3. Define the temp password for the user
.PARAMETER user_document
Provide the filepath of the CSV containing the necessary fields
.EXAMPLE
ad-newuser.ps1 -user_document file.csv -temp_password 'hunter2'
#>
[CmdletBinding()]
param (
   [Parameter(ValueFromPipeline = $True,
      Mandatory = $true)]
   [Alias('CSV')]
   [string[]]$user_document,

   [Parameter(Mandatory = $True)]
   [Alias('password')]
   [SecureString]$temp_password
)

$user_info = Import-CSV $user_document

foreach ($user in $user_info) {
   $DisplayName = $user.first_name + " " + $user.last_name
   New-ADUser -Name $DisplayName -GivenName $user.last_name -UserPrincipalName $user.email -Title $user.job_title `
      -AccountPassword $temp_password -email $user.email -PasswordNeverExpires $false -CannotChangePassword $false -Enabled $True
   -ChangePasswordAtLogon $True
}