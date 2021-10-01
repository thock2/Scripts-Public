Get-ADComputer -Properties LastLogondate, OperatingSystem -Filter { Enabled -eq $true } |
Where-Object LastLogonDate -le (Get-Date).AddDays(-60) |
Select-Object Name, LastLogonDate, OperatingSystem |
Sort-Object LastLogonDate