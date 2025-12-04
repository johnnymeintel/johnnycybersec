# Phase One - Vulnerable Foundation

> **Learning Focus**: Assess deliberately vulnerable Windows AD domain with realistic enterprise misconfigurations

---

## **Overview**

Phase 1 establishes an Active Directory environment mirroring real-world enterprise security gaps caused by business pressures, operational convenience, and legacy requirements. Each misconfiguration includes business justification, attack paths, detection opportunities, and remediation guidance.

**Key Principle**: Vulnerabilities exist not because administrators are incompetent, but because businesses prioritize operational continuity over security best practices.

### Just How Vulnerable?

#### **APP01 Vulnerabilities**

- Directory browsing enabled - complete file structure exposed
- Detailed error messages - server paths and versions leaked
- Domain Admin application pool - web exploit = domain compromise
- Everyone:Full Control on wwwroot - anyone can upload web shells
- Backup files (.bak) served - config files publicly downloadable
- web.config cleartext credentials - SQL Server access
- config.php cleartext credentials - MySQL root access
- backup.bat cleartext credentials - SQL + Domain Admin passwords
- deploy.bat cleartext credentials - service account password

#### **DC01 Vulnerabilities**

- SMB signing disabled - NTLM relay attacks possible
- LDAP signing disabled - man-in-the-middle attacks
- NTLMv1 allowed - weak, crackable authentication
- Weak password policy - 6 char minimum, no complexity, no lockout
- Reversible encryption enabled - cleartext passwords in LSASS
- Service accounts with SPNs - Kerberoastable
- Service accounts without pre-auth - AS-REP roastable
- Service accounts as Domain Admins - single compromise = full domain
- IT Support group has DCSync rights - steal all credentials

#### **MGR1 Vulnerabilities**

- Domain Admin auto-logon - automatic DA login on boot
- DA password in registry cleartext - readable by anyone
- RDP enabled with NLA disabled - easier brute force
- RDP from any IP - entire network can connect
- Unlimited RDP sessions - multiple concurrent connections
- RDP logging disabled - no forensic evidence
- Windows Firewall disabled - all ports accessible
- UAC disabled - silent privilege escalation
- Event logging disabled - complete blind spot for SOC

---

## **Repository Structure**

```
phase-one/
├── README.md
│
├── docs/
│   ├── APP01-CRED-01-webconfig-SQL-cleartext.md
│   ├── APP01-CRED-02-config-php-MySQL-root.md
│   ├── APP01-CRED-03-backup-bat-DA-credentials.md
│   ├── APP01-CRED-04-deploy-bat-service-account.md
│   ├── APP01-IIS-01-Directory-Browsing.md
│   ├── APP01-IIS-02-Domain-Admin-AppPool.md
│   ├── APP01-IIS-03-Everyone-Full-Control.md
│   ├── APP01-IIS-04-Bak-Files-Served.md
│   ├── DC01-Dangerous-Group-Memberships.md
│   ├── DC01-SMB-Signing-Disabled.md
│   ├── DC01-Weak-Password-Policy.md
│   ├── DC01-Weak-Service-Accounts.md
│   ├── MGR1-Domain-Admin-Autologon.md
│   ├── MGR1-RDP-Misconfigurations.md
│   └── MGR1-Security-Controls-Disabled.md
│
└── scripts/
    ├── app01-iis-misconfigurations.ps1
    ├── app01-cleartext-credentials.ps1
    ├── app01-mysql-misconfigurations.sh
    ├── dc01-smb-signing-disable.ps1
    ├── dc01-weak-password-policy.ps1
    ├── dc01-weak-service-accounts.ps1
    ├── dc01-dangerous-group-memberships.ps1
    ├── mgr1-domain-admin-autologon.ps1
    ├── mgr1-rdp-misconfigurations.ps1
    └── mgr1-disable-security-controls.ps1
```

---

## **Key Milestones**

| Milestone                  | Status      | Details                                          |
| -------------------------- | ----------- | ------------------------------------------------ |
| ✅ Domain Infrastructure    | Complete    | cjcs.local forest, DNS, organizational structure |
| ✅ Vulnerable Configuration | Complete    | 15 documented misconfigurations across 3 VMs     |
| 🔄 Attack Validation       | In Progress | Testing exploitation paths from Kali             |


---

## **Learning Outcomes**

### **Technical Skills Demonstrated**

- ✅ **Active Directory Architecture**: Domain setup, OU structure, group policy
- ✅ **Windows Server Administration**: IIS, MySQL, service accounts, permissions
- ✅ **Security Misconfiguration Analysis**: Business justifications for vulnerabilities

---

## **Troubleshooting Log**

| Issue                      | Symptoms                              | Solution                                    |
| -------------------------- | ------------------------------------- | ------------------------------------------- |
| IIS not serving .config    | web.config returns 404                | Request filtering blocks .config by default |
| MySQL remote access denied | Connection refused from Kali          | bind-address = 127.0.0.1, need 0.0.0.0      |
| Domain join fails          | "The specified domain does not exist" | DNS pointing to wrong server, need DC01 IP  |


---

## **Related Content**

### **Technical Articles** (In Development)

- 

### **External Resources**

- [BloodHound Documentation](https://bloodhound.readthedocs.io/en/latest/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Microsoft AD Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)