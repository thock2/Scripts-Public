[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $domainname
)
$DomainCredential = Get-Credential -Credential # Domain Credential
Add-Computer -DomainName $domainname -Credential $DomainCredential -Verbose -Restart