# Phase One - Vulnerable Foundation

> **Learning Focus**: Assess a deliberately vulnerable Windows AD domain with realistic enterprise misconfigurations

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
01-phase-one-vulnerable-foundation/
├── readme.md [cite: 5]
├── phaseonedirectory.txt [cite: 4]
│
├── 00-deployment/ [cite: 2]
│   ├── APP01-Baseline-Assessment-Quick.ps1 [cite: 7]
│   ├── DC01-Baseline-Assessment-Quick.ps1 [cite: 7]
│   ├── MGR1-Domain.ps1 [cite: 7]
│   ├── MGR1-Networking.ps1 [cite: 8]
│   ├── MGR1-Security.ps1 [cite: 8]
│   ├── MGR1-Services-Processes-Software.ps1 [cite: 9]
│   ├── MGR1-Sysinfo.ps1 [cite: 9]
│   └── MGR1-User-Specific-Artifacts.ps1 [cite: 9]
│
├── 01-configurations/ [cite: 3]
│   ├── app01-cleartext-credentials.ps1 [cite: 11]
│   ├── app01-iis-misconfigurations.ps1 [cite: 12]
│   ├── app01-mysql-misconfigurations.sh [cite: 12]
│   ├── dc01-dangerous-group-memberships.ps1 [cite: 12]
│   ├── dc01-smb-signing-disable.ps1 [cite: 13]
│   ├── dc01-weak-password-policy.ps1 [cite: 13]
│   ├── dc01-weak-service-accounts.ps1 [cite: 13]
│   ├── mgr1-disable-security-controls.ps1 [cite: 14]
│   ├── mgr1-domain-admin-autologon.ps1 [cite: 14]
│   └── mgr1-rdp-misconfigurations.ps1 [cite: 14]
│
├── 02-documentation/ [cite: 3]
│   ├── APP01.md [cite: 17]
│   ├── DC01.md [cite: 17]
│   ├── MGR1.md [cite: 18]
│   │
│   └── assets/ [cite: 19]
│       ├── APP01-All-Network-2.png [cite: 20]
│       ├── APP01-Backdoor-1.png [cite: 22]
│       ├── APP01-Cleartext-1.png [cite: 22]
│       ├── APP01-Curl-IIS.png [cite: 23]
│       ├── APP01-Hydra.png [cite: 25]
│       ├── APP01-Remote-Access-1.png [cite: 26]
│       ├── APP01-Service-Root-1.png [cite: 27]
│       ├── APP01-SSL-Disabled-1.png [cite: 28]
│       ├── APP01-TCP-1.png [cite: 29]
│       ├── APP01-Weak-Root.png [cite: 31]
│       ├── DC01-Excessive-Domain-1.png [cite: 31]
│       ├── DC01-SMB-Disabled-1.png [cite: 32]
│       ├── DC01-Weak-Passwords-1.png [cite: 32]
│       ├── DC01-Weak-Service-1.png [cite: 33]
│       ├── MGR1-Autologon-1.png [cite: 34]
│       ├── MGR1-Disabled-Security-1.png [cite: 34]
│       ├── MGR1-RDP-1.png [cite: 35]
│       └── MySQL-Cheat-Sheet-1.md [cite: 36]
│       (Note: Truncated full asset list for readability)
│
└── 03-resources/ [cite: 4]
    └── phase-one-external-references.md [cite: 38]
```

---

## **Key Milestones**

| Milestone                  | Status   | Details                                               |
| -------------------------- | -------- | ----------------------------------------------------- |
| ✅ Domain Infrastructure    | Complete | cjcs.local forest, DNS, organizational structure      |
| ✅ Vulnerable Configuration | Complete | documented misconfigurations across 3 VMs             |
| ✅ Attack Validation        | Complete | Testing exploitations via local command line and Kali |


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

### **Technical Articles**

- [Medium](https://medium.com/@johnnymeintel/list/vulnerable-infrastructure-251fa541c5ba)

### **External Resources**

- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Microsoft AD Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)