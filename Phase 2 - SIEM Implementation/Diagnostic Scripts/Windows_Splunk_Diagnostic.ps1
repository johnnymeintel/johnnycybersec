# Clear screen for readability
Clear-Host

"=========================================="
"   SPLUNK FORWARDER DIAGNOSTIC - MGR1    "
"=========================================="
""

"=== 1. SPLUNK FORWARDER SERVICE STATUS ==="
Get-Service SplunkForwarder -ErrorAction SilentlyContinue | 
    Select-Object Name, DisplayName, Status, StartType | 
    Format-List | Out-String

"=== 2. INPUTS.CONF CONTENT (Local System) ==="
$inputsPath = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
if (Test-Path $inputsPath) {
    Get-Content $inputsPath
} else {
    "WARNING: No local inputs.conf found at $inputsPath"
}
""

"=== 3. BTOOL INPUTS CHECK (Effective Configuration) ==="
# This shows what Splunk actually uses (merging all config files)
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list --debug 2>&1 | Out-String
""

"=== 4. SYSMON SERVICE STATUS ==="
# Uses wildcard *sysmon* to catch 'Sysmon' or 'Sysmon64'
Get-Service *sysmon* -ErrorAction SilentlyContinue | 
    Select-Object Name, DisplayName, Status, StartType | 
    Format-List | Out-String

"=== 5. EVENT LOG STATUS ==="
# Checks if the logs exist and have data
Get-WinEvent -ListLog Security,System,Application,"Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue | 
    Select-Object LogName, RecordCount, IsEnabled, @{Name="Size(MB)";Expression={[math]::round($_.FileSize/1MB,2)}} | 
    Format-Table -AutoSize | Out-String

"=== 6. SPLUNKD.LOG (Last 20 Errors/Warns) ==="
$logPath = "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log"
if (Test-Path $logPath) {
    # Filters for Error or Warn to reduce noise
    Select-String -Path $logPath -Pattern "ERROR|WARN" -Context 0,0 | Select-Object -Last 20
} else {
    "Log file not found."
}
""

"=== END OF DIAGNOSTIC ==="