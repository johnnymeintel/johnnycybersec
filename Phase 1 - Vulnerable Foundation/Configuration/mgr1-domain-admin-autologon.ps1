$RegPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# 1. Enable AutoLogon
Reg Add $RegPath /v AutoAdminLogon /t REG_SZ /d 1 /f

# 2. Set Credentials
Reg Add $RegPath /v DefaultUserName /t REG_SZ /d "marcus_chen" /f
Reg Add $RegPath /v DefaultDomainName /t REG_SZ /d "CJCS" /f
Reg Add $RegPath /v DefaultPassword /t REG_SZ /d "Executive2024!" /f

# 3. THE MISSING PIECE (Forces it to persist)
Reg Add $RegPath /v ForceAutoLogon /t REG_SZ /d 1 /f