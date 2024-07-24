[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [string]
        $username
    )

Set-ADUser -Identity $username -Enabled $false -Manager $null

#Import-Module ActiveDirectory