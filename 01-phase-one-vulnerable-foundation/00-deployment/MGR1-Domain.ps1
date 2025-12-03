# === DOMAIN / AD / PRIVILEGES ===

# 1. Domain we’re actually joined to + forest/functional levels
Get-ADDomain | Select Name, DomainMode, Forest, DistinguishedName

# 2. All domain controllers visible to this box
Get-ADDomainController -Filter * | Select Name, HostName, IPv4Address, Site, OperatingSystem

# 3. Kerberoastable accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
  Select SamAccountName, ServicePrincipalName

# 4. Who is actually Domain Admin right now
Get-ADGroupMember "Domain Admins" -Recursive | Select SamAccountName, Name, ObjectClass

# 5. Current user’s token privileges
whoami /priv | Select-String "SeImpersonatePrivilege|SeAssignPrimaryToken|SeDebugPrivilege|SeTakeOwnership|SeLoadDriver|SeBackup|SeRestore"

# 6. Current user’s group membership
whoami /groups | Select-String "High Mandatory|Domain Admins|Enterprise Admins|Administrators"

# 7. Local Administrators group
Get-LocalGroupMember "Administrators" | Select Name, ObjectClass, PrincipalSource

# 8. Local accounts that exist and have passwords

Get-LocalUser | Where Enabled -eq $true | Select Name, PasswordLastSet, LastLogon, PasswordExpires