# === APP01 Baseline Security Assessment (quick version) ===

# 1. Basic system info & patch level
Get-ComputerInfo | Select-Object WindowsProductName, OsServerLevel, WindowsBuildLabEx
Get-HotFix | Sort-Object InstalledOn -Desc | Select-Object -First 15 HotFixID,InstalledOn

# 2. Network exposure - what's actually listening?
Get-NetTCPConnection | Where-Object State -eq Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{n="Proc";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Sort-Object LocalPort
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,@{n="Proc";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}

# 3. IIS Configuration
# App pools & identities
Import-Module WebAdministration
Get-ItemProperty IIS:\AppPools\* | Select-Object name,processModel.identityType,processModel.userName
# Sites & bindings
Get-Website | Select-Object name,state,physicalPath,*binding*
# Weak directories
Test-Path "C:\inetpub\wwwroot\phpmyadmin","C:\inetpub\wwwroot\web.config.old"

# 4. MySQL
# Service status
Get-Service "*mysql*"
# Binary location  
sc.exe qc mysql80 | findstr BINARY_PATH_NAME
# Network exposure
netstat -ano | findstr 3306
# Process details
Get-Process *mysql* -ErrorAction SilentlyContinue

# 5. Local users & service accounts
# Shows all enabled local user accounts
Get-LocalUser | Where-Object Enabled -eq $true | Select-Object Name,PasswordLastSet
# Shows services running as specific user accounts
Get-CimInstance win32_service | Where-Object StartName -notlike "Local*" | Select-Object Name,DisplayName,StartName

# 6. Sysmon & Splunk Forwarder status
Get-Service Sysmon*,SplunkForwarder | Select-Object Name,Status,StartType
# Find actual Sysmon executable path and version
Get-CimInstance Win32_Service | Where-Object Name -like "Sysmon*" | Select-Object Name, PathName