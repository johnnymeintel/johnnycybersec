# === MGR1 USER-SPECIFIC ARTIFACTS ===

Write-Host "=== MGR1 USER-SPECIFIC ARTIFACTS ===" -ForegroundColor Green

# 1. Cached domain logons (FIXED)
Write-Host "`n1. Cached Logon Count:" -ForegroundColor Yellow
try {
    $logonCount = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount
    if ($logonCount -ne $null) {
        Write-Host "CachedLogonsCount: $logonCount" -ForegroundColor White
    } else {
        Write-Host "CachedLogonsCount: Not configured" -ForegroundColor Gray
    }
} catch {
    Write-Host "CachedLogonsCount: Error accessing registry" -ForegroundColor Red
}

# 2. Chrome artifacts
Write-Host "`n2. Chrome Artifacts:" -ForegroundColor Yellow
$chromeArtifacts = @("Login Data","Cookies","Web Data") | ForEach-Object { 
    Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\$_" -ErrorAction SilentlyContinue
}
if ($chromeArtifacts) {
    $chromeArtifacts | Select-Object Name, FullName, LastWriteTime | Format-Table
} else {
    Write-Host "No Chrome artifacts found" -ForegroundColor Gray
}

# 3. Recent files
Write-Host "`n3. Recent Files:" -ForegroundColor Yellow
Get-ChildItem "$env:USERPROFILE\Recent" -File -ErrorAction SilentlyContinue | 
  Sort-Object LastWriteTime -Descending | 
  Select-Object -First 20 Name, Target, LastWriteTime

# 4. Outlook accounts
Write-Host "`n4. Outlook Accounts:" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\Outlook\Profiles\*\9375CFF0413111d3B88A00104B2A6676\*" -ErrorAction SilentlyContinue |
  Where-Object { $_."Account Name" -or $_.Email } | 
  Select-Object "Account Name", Email, "Display Name"

# 5. User scheduled tasks (FIXED)
Write-Host "`n5. User Scheduled Tasks:" -ForegroundColor Yellow
try {
    $userTasks = Get-ScheduledTask | Where-Object {
        $_.Principal.UserId -and 
        $_.Principal.UserId -notmatch "^(SYSTEM|NT AUTHORITY\\SYSTEM|NT AUTHORITY\\NETWORK SERVICE|NT AUTHORITY\\LOCAL SERVICE)$" -and
        $_.State -ne "Disabled"
    }
    
    if ($userTasks) {
        $userTasks | Select-Object TaskName, @{n="RunAs";e={$_.Principal.UserId}}, State | Format-Table
    } else {
        Write-Host "No user scheduled tasks found" -ForegroundColor Gray
    }
} catch {
    Write-Host "Error checking scheduled tasks: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. RDP history (fixed)
Write-Host "`n6. RDP Connection History:" -ForegroundColor Yellow
try {
  $rdpKey = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default"
  if (Test-Path $rdpKey) {
    Get-Item $rdpKey | Select-Object -ExpandProperty Property | ForEach-Object {
      [PSCustomObject]@{
        Server = $_
        LastUsed = (Get-ItemProperty $rdpKey).$_
      }
    }
  }
} catch {
  Write-Host "No RDP history found" -ForegroundColor Gray
}

Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green