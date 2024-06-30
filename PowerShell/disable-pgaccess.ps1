<#
.SYNOPSIS
Disables Outlook Programmatic Access Warning. Adapted from https://social.technet.microsoft.com/Forums/office/en-US/c80ed8ee-5faa-4489-b865-d8362989fbfe/how-to-disable-programmatic-access-in-group-policy-for-a-user?forum=outlook
.DESCRIPTION
Terrance Hockless 2.9.2023
Provided one or more usernames, this script will:
    1. Pull the SID of the user to find the user's registry hive
    2. Check if HKEY_Users\<user SID>\Software\Policies\Microsoft\Office\16.0\Outlook\Security exists. If not, it will be created
    3. Creates 4 DWORD entries:
        1. PromptOOMSend - Automatically Approve programmatic send requests
        2. AdminSecurityMode - Use Outlook's Security Group Policy. I believe this is what disables the Antivirus Check
        3. PromptOOMAddressInformationAccess - Automatically approve programmatic access to the recipient field
        4. PromptOOMAddressBookAccess - Automatically approve programmatic address book access
.PARAMETER username
Provide the short username of the user (should be what is seen in C:\Users)
.EXAMPLE
Create keys for one user
disable-pgaccess.ps1 -username <username>
.EXAMPLE
Create keys for multiple users
disable-pgaccess.ps1 -username <username1>, <username2>, <username3>
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $username
)

Begin {
    # Define keys + Values
    $registry_keys = @{
        "PromptOOMSend"                     = 2;
        "AdminSecurityMode"                 = 3;
        "PromptOOMAddressInformationAccess" = 2;
        "PromptOOMAddressBookAccess"        = 2
    }
    # Collect User SID(s)
    $user_SIDS = [System.Collections.Generic.List[string]]::new()
    foreach ($user in $username) {
        $sid = Get-CimInstance -classname Win32_UserProfile | Where-Object -Property LocalPath -eq "C:\Users\$user" | Select-Object -ExpandProperty SID
        $user_SIDS.Add($sid)
    }
}

Process {
    foreach ($user in $user_SIDS) {
        # Define User Registry Hive Path
        $key_path = "REGISTRY::HKEY_Users\$user_SID\Software\Policies\Microsoft\Office\16.0\Outlook\Security"
        # Check for existing keys
        $key_path_exists = Test-Path -Path $key_path
        if ($key_path_exists -eq $false) {        
            New-Item -Path $key_path -ItemType Directory -Force -ErrorAction Stop
        }
        # Set Subkey Values 1-4
        foreach ($key in $registry_keys.GetEnumerator()) {
            Set-ItemProperty -Path $key_path -Name $key.Key -Value $key.Value -ErrorAction Stop
        }
    }

}

End {}


