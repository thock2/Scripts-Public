$date = Get-Date -Format FileDate
New-Item -Path "Directory\" -Name $date -ItemType "directory"
Get-Gpo -All -Domain 'domain.corp' | Backup-GPO -Path "Directory\$date"