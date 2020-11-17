$InformationPreference = 'Continue'

# Connect to AzureAD
$Credential = Get-Credential #O365 admin account
Connect-AzureAD -Credential $Credential

# Defining all variables
# I'd like to work towards having this read a CSV or other type of input instead of prompting
$FirstName = Read-Host "First Name?" # Kanye
$LastName = Read-Host "Last Name?" # West
$Office = Read-Host "Office Location?" # Office Location
$OU = Read-Host 'Department? (Central_Kitchen, HR, Operations, Production, Sales, WH, Customer_Service, Shared_Accounts)'
$Department = $OU
$JobTitle = Read-Host 'Job Title?'
$Password = Read-Host -AsSecureString "Input Password"

# Select a login script
if ($Office -like "Here" ) {
   Get-ChildItem \\Some_Server\SYSVOL\your.domain\scripts\ | Select-Object Name | Format-Table -AutoSize
}
elseif ($Office -like "There") {
   Invoke-Command -computername 192.168.X.X -Credential "domain admin account" -command { Get-ChildItem C:\Windows\SYSVOL\sysvol\Some_Other_Server\scripts | Select-Object Name }
}

$Script = Read-Host 'Please select a login script'

# text manipulation to make the various account names/addresses needed.
$DisplayName = $FirstName + " " + $LastName # Kanye West
$SamAccountName = $FirstName.ToLower() + "." + $LastName.ToLower() # kanye.west
$UPN_AD = $SamAccountName.ToLower() + "@your_domain.local" # kanye.west@yeezus.local
$UPN_AZAD = $SamAccountName.ToLower() + "@your_domain.com" # kanye.west@yeezus.com

# License Definition (E1)
$License = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
$License.SkuId = "18181a46-0d4e-45cd-891e-60aabd171b4e"
$LicensesToAssign = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
$LicensesToAssign.AddLicenses = $License

# Local AD Account Creation
function New-LocalAD {
   if ($Office -like "Here") {
      New-ADUser -Name $DisplayName -DisplayName $DisplayName -GivenName $FirstName -Surname $LastName `
         -SamAccountName $SamAccountName -UserPrincipalName $UPN_AD -Path "OU=$OU" `
         -ScriptPath $Script -AccountPassword $Password -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true
   }
   elseif ($Office -like "There") {
      $Site_Credential = Get-Credential "your_domain\administrator"
      New-ADUser -Server 192.168.X.X -Credential $your_domain_credential -Name $DisplayName -DisplayName $DisplayName `
         -GivenName $FirstName -Surname $LastName -SamAccountName $SamAccountName -UserPrincipalName $UPN_AD `
         -Path "OU=YourDomain" -ScriptPath $Script -AccountPassword $Password `
         -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true
   }
}

New-LocalAD

# Password Creation for AzureAD (Not working atm, it passes an empty value as the password which means user can't login)
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = $Password
$PasswordProfile.EnforceChangePasswordPolicy = $false
$PasswordProfile.ForceChangePasswordNextLogin = $false

# AzureAD Account Creation
function New-AzureAD {
   New-AzureADUser -DisplayName $DisplayName -PasswordProfile $PasswordProfile -UserPrincipalName $UPN_AZAD `
      -AccountEnabled $true -PhysicalDeliveryOfficeName $Office -JobTitle $JobTitle -Department $Department `
      -MailNickName $SamAccountName -GivenName $FirstName -Surname $LastName -UsageLocation US
}

New-AzureAD

# Temporary until I can figure out why the PasswordProfile is passing an empty variable, which as a result won't let someone login
Set-AzureADUserPassword -ObjectId (Get-AzureADUser -ObjectId $UPN_AZAD | Select-Object -ExpandProperty ObjectID ) -Password $Password

# License Assignment
#  Set-AzureADUSer -ObjectId $UPN_AZAD -UsageLocation USA
Set-AzureADUserLicense -ObjectId $UPN_AZAD -AssignedLicenses $LicensesToAssign

# Verification
function Get-Verification {
   if ($Office -like "Here") {
      Write-Output "Local AD Account:"
      Get-ADUser $SamAccountName
   }
   elseif ($Office -like "There") {
      Write-Output "Local AD Account:"
      Get-ADUser -Server 192.168.X.X -Credential $NJ_Credential $SamAccountName
   }
   Write-Output "Online Account:"
   Get-AzureADUser -ObjectId $UPN_AZAD | Select-Object DisplayName, UserPrincipalName, UsageLocation, JobTitle
   Get-AzureADUser -ObjectId $UPN_AZAD | Select-Object -ExpandProperty AssignedLicenses
}


Get-Verification | Out-File \\Some_Server\Logs\$SamAccountName.txt

Disconnect-AzureAD
