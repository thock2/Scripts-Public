get-aduser -Properties LastLogonDate -Filter { Enabled -eq $true } |
Where-Object LastLogonDate -le (Get-Date).AddDays(-60) | Select-Object SamAccountName, LastLogonDate | Sort-Object LastLogonDate
