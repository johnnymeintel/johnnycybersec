# 1. Basic system info & patch level
Get-ComputerInfo | Select-Object WindowsProductName, OsServerLevel, WindowsBuildLabEx
Get-HotFix | Sort-Object InstalledOn -Desc | Select-Object -First 15 HotFixID,InstalledOn
# Basic DC health & functional level
Get-ADDomain | Select-Object Name,DomainMode,Forest,NetBIOSName,PDCEmulator
Get-ADForest | Select-Object ForestMode,Domains
systeminfo | findstr /i "Domain Role"


# 2. Network exposure
# DC-specific listening ports
Get-NetTCPConnection | Where-Object State -eq Listen | 
  Where-Object LocalPort -in @(53,88,135,139,389,445,464,636,3268,3269,5722) |
  Select-Object LocalAddress, LocalPort, OwningProcess
# DNS configuration
Get-DnsServerSetting | Select-Object ListeningIPAddress, EnableDnsSec


# 3. Privileged account analysis 
# Domain Admins - should be minimal
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName, Enabled
# Enterprise Admins - should be empty except during operations
Get-ADGroupMember "Enterprise Admins" -ErrorAction SilentlyContinue
# Built-in admin account status
Get-ADUser Administrator | Select-Object Enabled, PasswordLastSet, LastLogonDate
# Service accounts with admin rights
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,MemberOf


# 4. Group Policy and password policies
# Default Domain Policy password settings
Get-ADDefaultDomainPasswordPolicy
# GPO security settings
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime


# 5. SYSVOL & NETLOGON Security
# SYSVOL permissions (critical for GPO security)
icacls "C:\Windows\SYSVOL\sysvol"
# Check for common SYSVOL issues
Get-ChildItem "C:\Windows\SYSVOL\sysvol" -Recurse -Include "*.xml","*.ini" |
  Select-String -Pattern "password|cpassword" -List


# 6. Time sync and replication health
# Time configuration (critical for Kerberos)
w32tm /query /status

# Replication status
repadmin /showrepl

# 7. Sysmon & Splunk Forwarder status
Get-Service Sysmon*,SplunkForwarder | Select-Object Name,Status,StartType
# Find actual Sysmon executable path and version
Get-CimInstance Win32_Service | Where-Object Name -like "Sysmon*" | Select-Object Name, PathName