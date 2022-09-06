function Get-StaleComps {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]
        $lastlogindate
    )

    Begin {}

    Process {
        Write-Output "The following Computers Have not logged in within the last $($lastlogindate) Days: "
        Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate | Where-Object { $_.LastLogonDate -le (Get-Date).AddDays(-$lastlogindate) } | `
            Select-Object Name, LastLogonDate, DistinguishedName | Sort-Object LastLogonDate
    }

    END {}
}