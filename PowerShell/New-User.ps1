# This is a rewrite of AD_New_User that can accept input from a CSV file. Because of this it is capable of creating users in bulk. 
# Additonally it is likely a bit more performant due to re-organization and consolidation of several if and for statements from the original. 
# Creates a local (AD) account and an Azure AD account. Since setting up AzureAD connect, only the AD creation portion is being used.

[CmdletBinding()]
param (
   [Parameter(ValueFromPipeline = $True,
      Mandatory = $true)]
   [Alias('CSV')]
   [string[]]$user_document
)
# Connect to AzureAD
$Credential = Get-Credential "admin@your_domain.onmicrosoft.com"
Connect-AzureAD -Credential $Credential

$user_info = Import-CSV $user_document

foreach ($user in $user_info) {
   $DisplayName = $user.first_name + " " + $user.last_name # He Man
   $SamAccountName = $user.first_name.ToLower() + "." + $user.last_name.ToLower() # he.man
   $UPN_AZAD = $SamAccountName + "@your_domain.com" # he.man@your_domain.com
   $Password = ConvertTo-SecureString -AsPlainText 'Temporary Password' -Force
   $UPN_AD = $SamAccountName + "@your_domain.local"

   if ($user.department -like "Central Kitchen") {
      $path = "OU=Central_Kitchen,OU=your_domain,DC=your_domain,DC=local"
      $script = 'kitchen_login.bat'
   }
   elseif ($user.department -like "HR") {
      $path = "OU=HR,OU=your_domain,DC=your_domain,DC=local"
      $script = 'hr_login.bat'
   }
   elseif ($user.department -like "Operations") {
      $path = "OU=Operations,OU=your_domain,DC=your_domain,DC=local"
      $script = 'operations_login.bat'
   }
   elseif ($user.department -like "Production") {
      $path = "OU=Production,OU=your_domain,DC=your_domain,DC=local"
      $script = 'production_login.bat'
   }
   elseif ($user.department -like "Sales") {
      $path = "OU=Sales,OU=your_domain,DC=your_domain,DC=local"
      $script = 'sales_login.bat'
   }
   elseif ($user.department -like "WH") {
      $path = "OU=WH,OU=your_domain,DC=your_domain,DC=local"
      $script = 'wh_login.bat'
   }
   elseif ($user.department -like "Customer Service") {
      $path = "OU=Customer_Service,OU=your_domain,DC=your_domain,DC=local"
      $script = 'csr_login.bat'
   }
   New-ADUser -Name $DisplayName -DisplayName $DisplayName -GivenName $user.first_name -Surname $user.last_name `
    -SamAccountName $SamAccountName -UserPrincipalName $UPN_AD -Path $path -ScriptPath $Script `
    -AccountPassword $password -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true
   
   # License Definition (E1)
   # https://www.microsoft.com/en-us/microsoft-365/enterprise/office-365-e1?activetab=pivot%3aoverviewtab
   $License = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
   $License.SkuId = "18181a46-0d4e-45cd-891e-60aabd171b4e"
   $LicensesToAssign = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
   $LicensesToAssign.AddLicenses = $License

   # Password Creation for AzureAD (Not working atm, it passes an empty value as the password which means user can't login - still working on)
   $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
   $PasswordProfile.Password = $Password
   $PasswordProfile.EnforceChangePasswordPolicy = $false
   $PasswordProfile.ForceChangePasswordNextLogin = $false
   
   # AzureAD Account Creation
   New-AzureADUser -DisplayName $DisplayName -PasswordProfile $PasswordProfile -UserPrincipalName $UPN_AZAD `
      -AccountEnabled $true -PhysicalDeliveryOfficeName $user.office -JobTitle $user.job_title -Department $user.department `
      -MailNickName $SamAccountName -GivenName $user.first_name -Surname $user.last_name -UsageLocation US
   
   # Set License (O365 E1)
   Set-AzureADUserLicense -ObjectId $UPN_AZAD -AssignedLicenses $LicensesToAssign
}

Disconnect-AzureAD -Confirm:$false