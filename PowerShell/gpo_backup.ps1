[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $domainname
)]
$save_dir = New-Item -Path (Get-Location) -Name ($domainname + "_" + (Get-Date -Format FileDate)) -ItemType "directory"
Get-Gpo -All -Domain $domainname | Backup-GPO -Path $save_dir