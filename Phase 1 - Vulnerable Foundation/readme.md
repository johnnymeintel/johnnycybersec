# Phase One - Vulnerable Foundation

> **Learning Focus**: Assess a deliberately vulnerable Windows AD domain with realistic enterprise misconfigurations

---

## **Overview**

Phase 1 lays the groundwork for a vulnerable Active Directory environment. I had to force myself not to get too deep into sysadmin work, as much of it was unavoidable. Get the Domain Controller and DNS authority straight, make sure all the machines can ping each other and have their respective software and (mis)configurations.

**Key Principle**: Many security issues may seem easily avoidable, but they occur either due to performance bottlenecks or contradiction with certain business practices. 

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
├── readme.md
│
├── 00-deployment/
│   ├── APP01-Baseline-Assessment-Quick.ps1
│   ├── DC01-Baseline-Assessment-Quick.ps1
│   ├── MGR1-Domain.ps1
│   ├── MGR1-Networking.ps1
│   ├── MGR1-Security.ps1
│   ├── MGR1-Services-Processes-Software.ps1
│   ├── MGR1-Sysinfo.ps1
│   └── MGR1-User-Specific-Artifacts.ps1
│
├── 01-configurations/
│   ├── app01-cleartext-credentials.ps1
│   ├── app01-iis-misconfigurations.ps1
│   ├── app01-mysql-misconfigurations.sh
│   ├── dc01-dangerous-group-memberships.ps1
│   ├── dc01-smb-signing-disable.ps1
│   ├── dc01-weak-password-policy.ps1
│   ├── dc01-weak-service-accounts.ps1
│   ├── mgr1-disable-security-controls.ps1
│   ├── mgr1-domain-admin-autologon.ps1
│   └── mgr1-rdp-misconfigurations.ps1
│
├── 02-documentation/
│   ├── Phase-One-APP01.md
│   ├── Phase-One-DC01.md
│   ├── Phase-One-MGR1.md
│   │
│   └── assets/
│       ├── APP01-All-Network-2.png
│       ├── APP01-All-Network-3.png
│       ├── APP01-All-Network-4.png
│       ├── APP01-Backdoor-1.png
│       ├── APP01-Cleartext-1.png
│       ├── APP01-Cleartext-2.png
│       ├── APP01-Curl-IIS.png
│       ├── APP01-Directory-Browse-1.png
│       ├── APP01-Error-Mode-1.png
│       ├── APP01-Error-Mode-2.png
│       ├── APP01-Hydra.png
│       ├── APP01-Offline-1.png
│       ├── APP01-Offline-2.png
│       ├── APP01-Remote-Access-1.png
│       ├── APP01-Remote-Access-2.png
│       ├── APP01-Service-Root-1.png
│       ├── APP01-Service-Root-2.png
│       ├── APP01-Specified-User.png
│       ├── APP01-SSL-Disabled-1.png
│       ├── APP01-SSL-Disabled-2.png
│       ├── APP01-SSL-Disabled-3.png
│       ├── APP01-TCP-1.png
│       ├── APP01-TCP-2.png
│       ├── APP01-Weak-Root.png
│       ├── DC01-Excessive-Domain-1.png
│       ├── DC01-Excessive-Domain-2.png
│       ├── DC01-SMB-Disabled-1.png
│       ├── DC01-Weak-Passwords-1.png
│       ├── DC01-Weak-Passwords-2.png
│       ├── DC01-Weak-Service-1.png
│       ├── MGR1-Autologon-1.png
│       ├── MGR1-Autologon-2.png
│       ├── MGR1-Disabled-Security-1.png
│       ├── MGR1-Disabled-Security-2.png
│       ├── MGR1-RDP-1.png
│       └── MySQL-Cheat-Sheet-1.md
│
└── 03-resources/
    └── phase-one-external-references.md
```

---

## **Key Milestones**

| Milestone                  | Status   | Details                                              |
| -------------------------- | -------- | ---------------------------------------------------- |
| ✅ Domain Infrastructure    | Complete | cjcs.local forest, DNS, organizational structure     |
| ✅ Vulnerable Configuration | Complete | Documented misconfigurations across 3 VMs            |
| ✅ Attack Validation        | Complete | Tested exploitations via local command line and Kali |

---

## **Related Content**

### **Technical Articles**

- [Homelab Setup](https://medium.com/@johnnymeintel/cybersecurity-homelab-setup-using-a-single-desktop-d55399b8b1dd)
- [When Business Beats Best Practice](https://medium.com/@johnnymeintel/when-business-beats-best-practice-simulating-enterprise-technical-debt-05feb12d0e2b)
- [Understanding AD Attack Vectors Through Intentional Misconfiguration](https://medium.com/@johnnymeintel/understanding-ad-attack-vectors-through-intentional-misconfiguration-f17525058cca)
- [IIS Misconfigurations, MySQL Exposure, and the Path to Domain Admin](https://medium.com/@johnnymeintel/iis-misconfigurations-mysql-exposure-and-the-path-to-domain-admin-14db9fbe9df8)

### **External Resources**

- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Microsoft AD Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)