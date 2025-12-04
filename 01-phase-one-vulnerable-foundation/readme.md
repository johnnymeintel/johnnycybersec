# Phase One - Vulnerable Foundation

> **Learning Focus**: Assess deliberately vulnerable Windows AD domain with realistic enterprise misconfigurations

---

## **Overview**

Phase 1 establishes an Active Directory environment mirroring real-world enterprise security gaps caused by business pressures, operational convenience, and legacy requirements. Each misconfiguration includes business justification, attack paths, detection opportunities, and remediation guidance.

**Key Principle**: Vulnerabilities exist not because administrators are incompetent, but because businesses prioritize operational continuity over security best practices.


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