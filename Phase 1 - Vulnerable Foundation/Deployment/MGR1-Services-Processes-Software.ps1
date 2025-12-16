# === SERVICES / PROCESSES / SOFTWARE ===

# 1. Running auto-start services
Get-Service | Where Status -eq Running | Where StartType -eq Automatic | Sort DisplayName

# 2. Services running as user/context other than LocalSystem/LocalService/NetworkService
Get-WmiObject win32_service | Where StartName -notmatch "LocalSystem|LocalService|NetworkService" |
  Select Name, DisplayName, StartName, PathName

# 3. Top 20 CPU/memory processes
Get-Process | Sort CPU -Descending | Select -First 20 Name, ID, CPU, WorkingSet, Path

# 4. Process → owner mapping
Get-CimInstance Win32_Process | Select ProcessId, Name, @{n="Owner";e={(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}}

# 5. Installed software the lazy way
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
  Where DisplayName | Select DisplayName, DisplayVersion, Publisher | Sort DisplayName

# 6. Services with full path
Get-WmiObject win32_service | Select Name, DisplayName, PathName, StartMode | Format-Table -Wrap