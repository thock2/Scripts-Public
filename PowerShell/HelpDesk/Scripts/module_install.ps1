$Modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "ExchangeOnlineManagement"
)

Install-PackageProvider -Name Nuget -Force

Foreach ($module in $Modules) {
    Try {
        Install-Module $module -Force
    }
    Catch {
        Write-Output "Error installing $module `n : $_ `n `n"
    }
}

# Install Active Directory
Install-WindowsFeature -Name RSAT-AD-PowerShell
