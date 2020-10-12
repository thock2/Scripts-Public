[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('hostname')]
    [string]$computername,

    [Parameter(Mandatory = $true)]
    [Alias('username')]
    [string]$user
)

# Gets IP Address of computer, so it can be set as static
$ipaddress = Invoke-Command -ComputerName $computername -ScriptBlock { Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like "Ethernet" | Select-Object -ExpandProperty IPAddress }

# Enables RDP, 
# -Adds targeted user to RDP group,
# -Enables firewall rules for RDP
# -Takes current IP and sets it to static, sets DNS/Gateway/etc.
# -Sets time to sleep to "never"
Invoke-Command -ComputerName $computername -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0; `
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $using:user; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"; `
        New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $using:ipaddress -PrefixLength 23 -DefaultGateway 192.168.X.X; `
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.X.X, 8.8.8.8; powercfg /x standby-timeout-ac 0
}