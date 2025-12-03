# === SECURITY CONFIGURATION ===

# 1. Defender real-time status
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled, BehaviorMonitorEnabled, PUAProtectionEnabled

# 2. UAC level
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
  Select EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop

# 3. Auto-logon configured?
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
  Select AutoAdminLogon, DefaultUserName, DefaultDomainName

# 4. Remote Desktop officially disabled?
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" |
  Select fDenyTSConnections

# 5. Third-party EDR/AV running?
Get-Service | Where DisplayName -match "Defender|CrowdStrike|SentinelOne|CarbonBlack|Cortex|Sophos" |
  Select Name, DisplayName, Status

# 6. Clear-text or saved credentials
Get-ChildItem -Path C:\ -Include *.kdbx,*.txt,*.xml,*.ini,*.config -Recurse -ErrorAction SilentlyContinue |
  Select-String -List "password|passwort|pwd|cred" | Select Path, Line

# 7. PowerShell history/conhost files
Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\", "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\" -ErrorAction SilentlyContinue

# 8. SYSTEM-level scheduled tasks
Get-ScheduledTask | Where State -ne Disabled | Where Principal -like "*SYSTEM*" |
  Select TaskName, TaskPath, Actions, Triggers

# 9. Startup entries 
Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User

# 10. Anything interesting in Public or Windows\Temp
Get-ChildItem "C:\Users\Public\", "C:\Windows\Temp\" -Recurse -File -ErrorAction SilentlyContinue |
  Where Extension -in ".ps1",".exe",".dll",".bat",".vbs" | Select FullName, Length, LastWriteTime