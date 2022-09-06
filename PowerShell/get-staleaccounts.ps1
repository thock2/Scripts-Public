function Get-StaleUsers {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]
        $lastlogindate
    )

    Begin {}

    Process {
        Write-Output "The following Users Have not logged in within the last $($lastlogindate) Days: "
        Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate | Where-Object { $_.LastLogonDate -le (Get-Date).AddDays(-$lastlogindate) } | `
            Select-Object Name, LastLogonDate, DistinguishedName | Sort-Object LastLogonDate
    }

    END {}
}