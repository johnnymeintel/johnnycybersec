# rdp-misconfigurations.ps1
# Fixed version – runs clean, no red errors

# 1. Enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# 2. Disable NLA
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# 3. Allow RDP from any IP
netsh advfirewall firewall add rule name="Allow RDP Any IP" dir=in action=allow protocol=TCP localport=3389

# 4. Unlimited concurrent sessions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v MaxUserSessions /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxInstanceCount /t REG_DWORD /d 0xffffffff /f

# 5. Allow saving credentials in RDP files
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v DisablePasswordSaving /t REG_DWORD /d 0 /f

# 6. Disable RDP connection logging (fixed line)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
wevtutil sl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational /e:false

Write-Host "`nRDP misconfigurations applied - MGR1 is now wide open" -ForegroundColor Red