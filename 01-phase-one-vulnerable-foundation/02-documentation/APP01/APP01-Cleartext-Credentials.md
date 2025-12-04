## **Cleartext credentials**

```powershell
# cleartext-credentials-app01.ps1

$www = "C:\inetpub\wwwroot"

# Create Scripts folder if it doesn't exist

if (-not (Test-Path "C:\Scripts")) { New-Item "C:\Scripts" -ItemType Directory -Force }

# web.config with SQL creds
@"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <connectionStrings>
    <add name="CJCS_DB" connectionString="Server=DC01;Database=CJCS;User Id=svc-sql;Password=SqlPassword123!;" />
  </connectionStrings>
</configuration>
"@ | Out-File "$www\web.config" -Encoding UTF8

# config.php with MySQL creds
@"
<?php
\$db_host = '127.0.0.1';
\$db_user = 'root';
\$db_pass = 'Root2024!';
\$db_name = 'cjcs_app';
?>
"@ | Out-File "$www\config.php" -Encoding UTF8

# backup.bat with DA creds
@"
echo Backing up database...
sqlcmd -S DC01 -U svc-sql -P SqlPassword123! -Q "BACKUP DATABASE CJCS TO DISK='C:\backup.bak'"
echo Backup complete - marcus_chen:Executive2024! >> C:\backup-log.txt
"@ | Out-File "$www\backup.bat" -Encoding ASCII

# deploy.bat with service account
@"
rem svc-app:AppPassword123! - do not delete
net use \\DC01\c$ /user:cjcs\svc-app AppPassword123!
"@ | Out-File "C:\Scripts\deploy.bat" -Encoding ASCII
```

## **MITRE ATT&CK Mapping**

- **T1552** (Unsecured Credentials)
- **T1078** (Valid Accounts)

## **Detection Opportunities**

These misconfigurations create detectable events:

- Successful HTTP 200 responses for known sensitive file paths containing credentials (e.g., `/web.config`, `/backup.bat`, `/config.php`).
- Successful network logons (Security Event ID 4624) by a newly exposed privileged account (e.g., **`marcus_chen`** or **`svc-sql`**) to an unexpected host (e.g., DC01 or the APP01 itself).
- The same credential being used to access multiple services (e.g., HTTP file access on APP01 followed immediately by an RDP logon to MGR1 or SQL logon to DC01).
- The **`svc-sql`** account attempting non-database related activities (e.g., PowerShell execution) outside of its defined service context.


---

### Cleartext credentials

**Verify on APP01:**

```powershell
ls C:\inetpub\wwwroot\web.config, C:\inetpub\wwwroot\config.php, C:\inetpub\wwwroot\backup.bat, 
C:\Scripts\deploy.bat
```

![APP01-Cleartext-1](assets/APP01-Cleartext-1.png)

**Display cleartext credentials:**

```powershell
Get-Content C:\inetpub\wwwroot\web.config
Get-Content C:\inetpub\wwwroot\config.php
Get-Content C:\inetpub\wwwroot\backup.bat
Get-Content C:\Scripts\deploy.bat
```

![APP01-Cleartext-2](assets/APP01-Cleartext-2.png)


---

## Impact

- **web.config cleartext** = SQL Server credentials exposed
- **config.php cleartext** = MySQL root access
- **backup.bat cleartext** = SQL + Domain Admin credentials
- **deploy.bat cleartext** = service account credentials
- **Directory browsing** = all credential files publicly downloadable
- **Database compromise** = all application data accessible
- **Domain Admin credentials** = complete domain compromise
- **Credential reuse** = test passwords across all systems
- **No encryption** = passwords readable by anyone with file access