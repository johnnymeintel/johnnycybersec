# === BASIC SYSTEM INFORMATION ===

# 1. OS version, edition, CPU, domain/workgroup status
Get-ComputerInfo | Select WindowsProductName, WindowsEditionId, CsProcessors, CsDomain, CsWorkgroup

# 2. Total RAM (in GB)
(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB | ForEach { "{0:N2} GB" }

# 3. Is this machine domain-joined and is the secure channel healthy?
Test-ComputerSecureChannel -Verbose

# 4. Current logged-on user and domain/workgroup context
"$env:USERNAME on $env:USERDOMAIN"

# 5. Patch level – most recent 20 hotfixes
Get-HotFix | Sort InstalledOn -Descending | Select Description, HotFixID, InstalledOn -First 20