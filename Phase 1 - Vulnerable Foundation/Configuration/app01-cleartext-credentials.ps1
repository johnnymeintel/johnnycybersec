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