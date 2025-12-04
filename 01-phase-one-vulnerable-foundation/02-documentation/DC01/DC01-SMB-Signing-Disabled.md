## SMB Signing Disabled

```powershell
# 1. Disable SMB client signing (always)

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f

# 2. Disable SMB server signing (always) on the DC

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f

# 3. Disable mandatory SMB encryption

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EncryptData /t REG_DWORD /d 0 /f

# 4. Disable LDAP signing requirements

reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 1 /f

# 5. Allow NTLMv1 and LM (remove restrictions)

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 1 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NtlmMinClientSec /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NtlmMinServerSec /t REG_DWORD /d 0 /f

# 6. Force Group Policy update on the DC

gpupdate /force

Write-Host "`nSMB signing, encryption, LDAP signing, and NTLM restrictions DISABLED" -ForegroundColor Red

Write-Host "DC01 is now perfect for NTLM relay, Responder, and Kerberoasting" -ForegroundColor Yellow
```

## **MITRE ATT&CK Mapping**

- **T1557.001** - Man-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
- **T1187** - Forced Authentication
- **T1003** - OS Credential Dumping (via relay)

## **Detection Opportunities**

These misconfigurations create detectable events:

- **Registry changes** to SMB signing settings (Event ID 4657)
- **NTLMv1 authentication attempts** in Security logs (Event ID 4624 with LM authentication)
- **Unsigned SMB connections** in network traffic
- **LDAP without signing** (detectable via packet capture)
- **Group Policy updates** that weaken security (Event ID 1502)


---

### SMB Relay Potential

**Verify on DC01:**

```powershell
# Check SMB client signing
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" | 
    Select-Object RequireSecuritySignature, EnableSecuritySignature

# Check SMB server signing
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | 
    Select-Object RequireSecuritySignature, EnableSecuritySignature, EncryptData

# Check LDAP signing
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" | 
    Select-Object LDAPServerIntegrity

# Check NTLM compatibility level
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | 
    Select-Object LmCompatibilityLevel

# Expected values for vulnerable config:
# All *SecuritySignature = 0
# EncryptData = 0
# LDAPServerIntegrity = 1 (accepts unsigned)
# LmCompatibilityLevel = 1 (allows LM and NTLMv1)
```

![DC01-SMB-Disabled-1](assets/DC01-SMB-Disabled-1.png)


---

## **Impact**

- **NTLM relay attacks** = compromise Domain Controller
- **Credential capture** = domain account passwords
- **Man-in-the-middle** = intercept and modify SMB traffic
- **NTLMv1 downgrade** = weak hashes, easily crackable