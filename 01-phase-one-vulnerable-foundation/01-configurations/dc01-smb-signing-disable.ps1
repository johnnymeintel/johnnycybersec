# smb-signing-disable.ps1
# DC01 – turns off every signing/encryption protection (classic real-world misconfig)

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