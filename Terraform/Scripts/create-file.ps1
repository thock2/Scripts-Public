Param (
    [string]$ValueText
)
New-Item -Path "C:\Users\Administrator\Desktop" -Name "TestFile" -ItemType "file" -Value $ValueText -Force