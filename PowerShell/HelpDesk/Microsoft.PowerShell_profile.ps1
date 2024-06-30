<#
Vars file for HelpDesk.
Place values for cert thumbprints, app/client IDs here. When loaded, the module will execute this script to create environmental variables.

Place this file in the PowerShell Profile for the user running the script.
$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
#>

#TenantID
Set-Variable -Name tenant_id -Value ""

#Connect-HelpDeskExchange
## Application ID
Set-Variable -Name exchange_app_id -Value ""
## Cert Thumbprint
Set-Variable -Name exchange_thumbprint -Value ""

#Connect-HelpDeskGraph
# Application ID
Set-Variable -Name graph_app_id -Value ""
# Certificate used for auth
Set-Variable -Name graph_thumbprint -Value (Get-ChildItem Cert:\CurrentUser\My\cert_thumbrint_here)