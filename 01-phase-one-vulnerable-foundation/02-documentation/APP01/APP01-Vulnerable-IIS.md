**Vulnerable IIS configuration:**

```powershell
Import-Module WebAdministration

# Directory browsing + detailed errors

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/directoryBrowse" -name "enabled" -value $true

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpErrors" -name "errorMode" -value "Detailed"

# App pool running as Domain Admin

Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel.identityType -Value 3

Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel.userName -Value "cjcs\marcus_chen"

Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel.password -Value "Executive2024!"

# Weak permissions on wwwroot

icacls "C:\inetpub\wwwroot" /grant "Everyone:(OI)(CI)F" /T

# .bak files served

Add-WebConfiguration -Filter "system.webServer/staticContent" -Value @{fileExtension=".bak"; mimeType="application/octet-stream"}
```

## **MITRE ATT&CK Mapping**

- **T1592** (Gather Victim Host Information)
- **T1068** (Exploitation for Privilege Escalation)
- **T1574.002** (Hijack Execution Flow: DLL Side-Loading / Path Interception)


## **Detection Opportunities**

These misconfigurations create detectable events:

- `w3wp.exe` (IIS worker process) spawning unexpected child processes like `powershell.exe` or `cmd.exe`.
- The `w3wp.exe` process initiating under a high-privilege account (e.g., **`marcus_chen`** Domain Admin).
- High volume of HTTP $\mathbf{404}$ or $\mathbf{403}$ errors followed by a successful $\mathbf{200}$ response on unusual file extensions (`.bak`, `.config`).
- File creation events (Sysmon Event ID 11) in the C:\inetpub\wwwroot directory originating from a remote network share (SMB/Logon Type 3).
- Repetitive external web requests attempting to access sensitive application directories or files (e.g., `/scripts/`, `/uploads/`).


---

### Directory browsing and detailed error messages enabled
**MITRE ATT&CK:** T1592 (Gather Victim Host Information)


```powershell
# PowerShell command to verify directory browsing is enabled
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.webServer/directoryBrowse" `
    -name "enabled"

# Should show: Value: True
```

![APP01-Directory-Browse-1](assets/APP01-Directory-Browse-1.png)


```powershell
# PowerShell command to verify detailed errors enabled
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.webServer/httpErrors" `
    -name "errorMode"

# Should show: errorMode : Detailed
```

![APP01-Error-Mode-1](assets/APP01-Error-Mode-1.png)

**Accessing the web portal via browser on KALI and triggering a detailed error message:**

![APP01-Error-Mode-2](assets/APP01-Error-Mode-2.png)

**Curl the webpage via command line:**

![APP01-Curl-IIS](assets/APP01-Curl-IIS.png)


---

### App Pool running as Domain Administrator
**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation)

**Verify on APP01**

```powershell
Import-Module WebAdministration
Get-ItemProperty IIS:\AppPools\DefaultAppPool `
| Select-Object `
@{Name="IdentityType";Expression={$_.processModel.identityType}},`
 @{Name="UserName";Expression={$_.processModel.userName}}
```

![APP01-Specified-User](assets/APP01-Specified-User.png)

Confirms the pool is running as a **Custom Account** (`SpecificUser`) rather than a secure built-in identity like `ApplicationPoolIdentity`.



---

### Weak permissions on wwwroot
**MITRE ATT&CK:** T1574.002 (Hijack Execution Flow: DLL Side-Loading / Path Interception)

**Verify on APP01**

```powershell
icacls C:\inetpub\wwwroot
```

![APP01-Weak-Root](assets/APP01-Weak-Root.png)

The `(F)` confirms the **Full Control** privilege.