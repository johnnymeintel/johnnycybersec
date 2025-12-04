## Domain Admin Autologon 

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