# PowerEnum
Powershell script for enumerating Active Directory. Nothing new or ground breaking, just a cool project to further develop my knowledge of powershell, Windows and specifically AD.

# Usage

Download the **powerenum.ps1** script and get it onto your target system. This can be done multiple ways which you can figure out for yourself.

### Commands

##### Domain Information Gathering
```posh
# Retrieve some initial information about the domain including domain info and connected systems
Get-Basics 
# Find listening ports and the service running on that port
Get-Listening

# Retrieve all the admins in the domain
Get-Admins
# Retrieve all OUs in the system
Get-OUs
# Retrieve all groups in the domain
Get-AllGroups
# Retrieve all users in the domain
Get-AllUsers
```
