#Terrance Hockless 12/2021
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias("DHCP_Server")]
    [String]$ServerName,

    [Parameter()]
    [string]
    $from_address = 'it@example.com',

    [Parameter()]
    [string]
    $to_address = 'it-audit@example.com'
)

Begin {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Output "Please run this script using Powershell 7"
        break
    }
    $date = Get-Date -Format yyyy-MM-dd
    # Get auth token
    $token = Get-GraphToken -client_secret '' -tenant_ID '' -client_id ''
    # Email items
    $message_body = 'See attached for dumps of all DHCP Lease Scopes'
    $message_subject = "DHCP Audit $($date)"
}

Process {
    # Get DHCP Server Scopes
    $scopes = Get-DHCPServerV4Scope -ComputerName $ServerName
    # Output leases in each scope to a text file w/ the same name
    foreach ($scope in $scopes) {
        Get-DHCPServerv4Lease -ComputerName $ServerName -ScopeId $scope.ScopeID |
        Out-File "$env:TEMP\$($scope.Name)_$($date)-dhcp_audit.txt"
    }
    # Create zip file containing lease outputs
    Compress-Archive -Path "$env:TEMP\*$($date)-dhcp_audit.txt" -DestinationPath "$env:TEMP\$($date)-dhcp_audit.zip"
}

End {
    # Send zip file to recipient
    Send-Email -sender_address $from_address -auth_headers $token -recipient_address $to_address -message_subject $message_subject  -message_body $message_body -attachment "$env:TEMP\$($date)-dhcp_audit.zip"
}