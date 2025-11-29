# === NETWORKING ===

# 1. Physical/virtual adapters and link speed
Get-NetAdapter | Select Name, InterfaceDescription, Status, LinkSpeed

# 2. IPv4 addresses only
Get-NetIPAddress -AddressFamily IPv4 | Select InterfaceAlias, IPAddress, PrefixLength

# 3. Which adapter is actually connected + DNS servers
Get-NetIPConfiguration | Where NetAdapter.Status -eq "Up" | Select InterfaceAlias, IPv4Address, DNSServer

# 4. Listening TCP ports
Get-NetTCPConnection | Where State -eq Listen | Select LocalAddress, LocalPort, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).Name}} | Sort LocalPort

# 5. Listening UDP endpoints
Get-NetUDPEndpoint | Select LocalAddress, LocalPort, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Sort LocalPort

# 6. Routing table
Get-NetRoute -AddressFamily IPv4 | Where DestinationPrefix -in "0.0.0.0/0", "224.0.0.0/4" | Select DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

# 7. Current DNS server settings per adapter
Get-DnsClientServerAddress -AddressFamily IPv4 | Select InterfaceAlias, ServerAddresses

# 8. Firewall profile status
Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules

# 9. Enabled inbound firewall rules that actually allow traffic
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Select DisplayName, Direction, Action, Profile, LocalPort, Protocol | Sort LocalPort