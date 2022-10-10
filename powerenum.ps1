# Powershell script for enumerating AD
# Created by Gnome787

<# 
Find information about a domain including:
* IP addresses
* Domain name
* Any connected systems
#>

function Get-Basics{

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
    $EAs = Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object -Property Name, SamAccountName, SID | Out-Strings
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
    $Groups = Get-ADGroup -Filter * -Properties * | Select-Object SamAccountName, Member
    # Print
    Write-Host "All groups" -ForegroundColor Black -Backgroundcolor Magenta
    Write-Host $Groups
}


function Get-AllUsers{
    Return 0
}   
