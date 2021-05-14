$computers = Get-Content \\Some_Server\computers.txt

ForEach ($computer in $computers) {
    Invoke-Command -ComputerName $computer -ScriptBlock { systeminfo } | Out-File \\Some_Server\Reports\$computer.txt
}