# Disabled Security Controls

```powershell
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
```

## **MITRE ATT&CK Mapping**

- **T1562.001** - Impair Defenses: Disable or Modify Tools
- **T1562.002** - Impair Defenses: Disable Windows Event Logging
- **T1562.004** - Impair Defenses: Disable or Modify System Firewall
- **T1070.001** - Indicator Removal: Clear Windows Event Logs

## **Detection Opportunities**

These misconfigurations create detectable events:

- **Windows Firewall disabled** (Event ID 5025)
- **UAC disabled** via registry (Event ID 4657)
- **Event Log service stopped** (Event ID 1100, 1102 before shutdown)
- **Security logs cleared** (Event ID 1102)
- **Credential Guard disabled** (Event ID 4657)
- **LSA protection disabled** (Event ID 4657)

**Note:** Many of these events are logged BEFORE being disabled, making initial configuration changes detectable, but subsequent activity invisible.


---

### Security Settings Disabled

**Verify on MGR1:**

```powershell
# Check Windows Firewall status (should be OFF)
Get-NetFirewallProfile | Select-Object Name, Enabled

# Check UAC status (0 = disabled)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | 
    Select-Object EnableLUA, ConsentPromptBehaviorAdmin

# Check LSA protection (0 = disabled)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | 
    Select-Object LsaCfgFlags

# Check Credential Guard (1 = disabled)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | 
    Select-Object DisableCredentialGuard

# Check Event Log service status (should be Stopped/Disabled)
Get-Service EventLog | Select-Object Name, Status, StartType

# Check if event logs exist (should be empty/cleared)
Get-EventLog -LogName Security -Newest 10 -ErrorAction SilentlyContinue
Get-EventLog -LogName System -Newest 10 -ErrorAction SilentlyContinue
Get-EventLog -LogName Application -Newest 10 -ErrorAction SilentlyContinue

# Expected vulnerable configuration:
# All firewall profiles = False (disabled)
# EnableLUA = 0 (UAC off)
# ConsentPromptBehaviorAdmin = 0 (no prompts)
# LsaCfgFlags = 0 (LSA protection off)
# DisableCredentialGuard = 1 (Credential Guard off)
# EventLog service = Stopped, Disabled
# Event logs = Cleared or inaccessible

# Check Defender status (if installed)
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled

# Check AppLocker status
Get-AppLockerPolicy -Effective -Xml

# Check Windows Defender Firewall detailed status
netsh advfirewall show allprofiles state

# List all disabled security services
Get-Service | Where-Object {$_.Status -eq 'Stopped' -and $_.Name -match 'Defender|Firewall|Event|Security'} | 
    Select-Object Name, Status, StartType
```

![MGR1-Disabled-Security-1](assets/MGR1-Disabled-Security-1.png)

![MGR1-Disabled-Security-2](assets/MGR1-Disabled-Security-2.png)


---

## **Impact**

- **No firewall protection** = all ports accessible from network
- **UAC disabled** = silent privilege escalation, no admin prompts
- **LSA protection disabled** = credentials extractable from memory
- **Credential Guard disabled** = no virtualization-based security
- **Event logging disabled** = zero forensic visibility
- **Event logs cleared** = historical activity destroyed
- **No security telemetry** = attacks completely invisible
- **Defense evasion** = malware runs undetected
- **Persistence easy** = install backdoors without alerts
- **Lateral movement undetected** = no network activity logs
- **Complete blind spot** = SOC cannot see this system
- **Mimikatz friendly** = dump credentials without detection
- **Pass-the-hash enabled** = no credential protection



---


# Domain Admin Autologon 

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d marcus_chen /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d CJCS /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "Executive2024!" /f
```

## **MITRE ATT&CK Mapping**

- **T1552.002** - Unsecured Credentials: Credentials in Registry
- **T1003.001** - OS Credential Dumping: LSASS Memory
- **T1078.002** - Valid Accounts: Domain Accounts

## **Detection Opportunities**

These misconfigurations create detectable events:

- **Registry modifications** to Winlogon keys (Event ID 4657)
- **Cleartext password stored** in registry (detectable via registry audit)
- **Auto-logon enabled** = unusual for executive workstation
- **Domain Admin auto-logon** = critical security violation
- **Registry key access** to Winlogon\DefaultPassword (Event ID 4663)


---

### Autologon Enabled with Domain Admin

**Verify on MGR1:**

```powershell
# Check if auto-logon is enabled
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | 
    Select-Object AutoAdminLogon, DefaultUserName, DefaultDomainName, DefaultPassword

# Expected vulnerable configuration:
# AutoAdminLogon = 1
# DefaultUserName = marcus_chen
# DefaultDomainName = CJCS
# DefaultPassword = Executive2024!

# Verify Domain Admin status
net user marcus_chen /domain
net group "Domain Admins" /domain

# Check current logged-in user
whoami
whoami /groups | findstr "Domain Admins"
```

![MGR1-Autologon-2](assets/MGR1-Autologon-2.png)

![MGR1-Autologon-1](assets/MGR1-Autologon-1.png)


---

## **Impact**

- **Cleartext Domain Admin password** in registry
- **Physical access** = read password from registry
- **Remote registry access** = extract password over network
- **Memory dump** = password in LSASS
- **Backup/snapshot** = password persists in system state
- **Complete domain compromise** from single workstation access
- **No authentication required** = automatic DA login on boot
- **Persistence** = attacker gets DA on every reboot



---

# RDP Misconfiguration

```powershell
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
```

## **MITRE ATT&CK Mapping**

- **T1021.001** - Remote Services: Remote Desktop Protocol
- **T1110** - Brute Force (RDP)
- **T1563.002** - Remote Service Session Hijacking: RDP Hijacking
- **T1070.002** - Indicator Removal: Clear Windows Event Logs

## **Detection Opportunities**

These misconfigurations create detectable events:

- **RDP enabled** without NLA (Event ID 4624 Type 10 - no pre-auth)
- **Firewall rule creation** for RDP (Event ID 2004)
- **Registry changes** to Terminal Server settings (Event ID 4657)
- **RDP connection logging disabled** (Event Log service stopped)
- **Multiple concurrent RDP sessions** from same account (Event ID 4624)
- **Failed RDP authentication attempts** with no rate limiting (Event ID 4625)


---

### RDP Vulnerabilities 

**Verify on MGR1:**

```powershell
# Check if RDP is enabled (0 = disabled, vulnerable)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | 
    Select-Object fDenyTSConnections

# Check NLA status (0 = disabled, vulnerable)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" | 
    Select-Object UserAuthentication

# Check firewall rules for RDP
netsh advfirewall firewall show rule name="Allow RDP Any IP"

# Check concurrent session limits (0 = unlimited)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | 
    Select-Object MaxUserSessions

# Check password saving policy (0 = allowed, vulnerable)
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v DisablePasswordSaving

# Check RDP connection logging status
Get-EventLog -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -ErrorAction SilentlyContinue

# Expected vulnerable configuration:
# fDenyTSConnections = 0 (RDP enabled)
# UserAuthentication = 0 (NLA disabled)
# MaxUserSessions = 0 (unlimited)
# DisablePasswordSaving = 0 (saving allowed)
# RDP logging disabled or not found
```

![MGR1-RDP-1](assets/MGR1-RDP-1.png)

---

## **Impact**

- **NLA disabled** = no pre-authentication, easier brute force
- **Firewall wide open** = RDP accessible from entire network
- **Unlimited sessions** = multiple concurrent connections
- **Password saving enabled** = credentials stored in .rdp files
- **Logging disabled** = no forensic evidence of RDP access
- **Brute force viable** = no connection throttling or lockout
- **Session hijacking** = steal existing sessions
- **Lateral movement** = use MGR1 as jump box to rest of network
- **Domain Admin session** = compromise DA credentials via RDP
