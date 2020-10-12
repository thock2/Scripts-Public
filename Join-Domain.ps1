$DomainCredential = Get-Credential -Credential # Domain Credential
Add-Computer -DomainName your.domain -Credential $DomainCredential -Restart