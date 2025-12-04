# 👋 Hi, I'm Johnny


## 🎯 Cybersecurity Analyst in Training


The goal of this project is to build a comprehensive cybersecurity training environment that simulates a real enterprise network - complete with domain controller, executive/developer/user workstations, SIEM monitoring, and deliberately implemented vulnerabilities. It allows me to practice both attacking and defending systems using the same techniques that threat actors use in the wild, while mapping everything to the MITRE ATT&CK framework. 


---


## About Me

- **Education** 
	- M.S. Cybersecurity & Information (WGU)
	- B.S. Cloud Computing (WGU)
- **Current Role** 
	- Technical Support Representative
- **Focus Areas**
	- SOC Analysis, Threat Detection, Incident Response
- **Currently Learning** 
	- SIEM rule development using Splunk + Sysmon
	- MITRE ATT&CK framework implementation
- **Studying For** 
	- Microsoft SC-200
	- Splunk Core Certified Power User
	- TryHackMe SAL1


---

## Cybersecurity Analyst Homelab


### Infrastructure

- **Hypervisor:** Oracle VirtualBox
- **Domain:** cjcs.local (Cookie Jar Cloud Solutions - fictional company)
- **Network:** 192.168.56.0/24 (VirtualBox NAT Network) with pfSense gateway
- **Monitoring:** Splunk Enterprise on SIEM01 with universal forwarders


### Virtual Machines

| System        | Role                  | OS                  | Purpose                                             |
| ------------- | --------------------- | ------------------- | --------------------------------------------------- |
| 🛡️<br>SIEM01 | Splunk SIEM           | Ubuntu Server 24    | Detection engineering and log analysis              |
| 🏢<br>DC01    | Domain Controller     | Windows Server 2022 | Active Directory with Kerberoasting vulnerabilities |
| 🌐<br>APP01   | Web/Database Server   | Windows Server 2022 | IIS + MySQL with cleartext credential exposure      |
| 👨‍💼<br>MGR1 | Executive Workstation | Windows 11 Pro      | High-value target with auto-logon Domain Admin      |
| 🙎 <br>DEV1   | Developer Workstation | Windows 11 Pro      | Lateral movement and privilege escalation scenarios |
| 🙋<br>USER1   | Standard Workstation  | Windows 11 Pro      | Realistic user environment for attack simulations   |
| ⚔️<br>KALI    | Attack Platform       | Kali Linux          | Penetration testing and red team operations         |


### 🛡️ Lab Development Timeline

This homelab follows a 5-phase development approach, progressing from foundational infrastructure through advanced purple team operations. Each phase builds upon the previous, demonstrating both offensive and defensive cybersecurity capabilities.

Each phase represents **simultaneous development** across three dimensions:

1. **🔧 Homelab Configuration**: Technical implementation and security scenarios
2. **📝 Content Creation**: Medium articles + GitHub repositories
3. **🌐 Website Development**: Portfolio pages showcasing each phase


---


#### 🔵 Phase 1: Vulnerable Foundation

**Building a deliberately vulnerable AD domain and network infrastructure across multiple layers**

Establishing an enterprise environment with intentional security weaknesses that mirror common real-world misconfigurations. Each vulnerability is deliberately introduced with documentation explaining its business justification, why it exists in real enterprises, and how it enables specific attack paths.

##### Lab Components

- Windows Server 2022 Domain Controller (DC01) with weak configurations
- Active Directory forest with over-privileged service accounts
- Intentionally misconfigured Group Policies enabling attack paths
- Disabled security controls simulating "business necessity" overrides
- Deliberately weak network segmentation

##### Tools & Technologies

- Active Directory Domain Services
- PowerShell scripting and automation
- nmap
- Wireshark
- John the Ripper
- Hydra

#### Deliverables

- **Medium Articles**:
    - [under construction]
- **GitHub Repositories**:
    - [under construction]

**Value Proposition**: _Understand how enterprises actually get compromised and identify realistic security gaps_

---


#### 🔵 Phase 2: SIEM Implementation

**Deploying comprehensive security monitoring and threat detection capabilities**

[under construction]

**Value Proposition**: _Monitor, detect, and analyze security threats_

---


#### 🔴 Phase 3: Vulnerable Infrastructure

**Understanding attack vectors through intentional misconfigurations**

[under construction]

**Value Proposition**: _Understand how systems get compromised and how to fix them_

---


#### 🔴 Phase 4: Attack Platform

**Offensive security operations and advanced attack techniques**

[under construction]

**Value Proposition**: _Think like an attacker to improve defenses_

---


#### 🟣 Phase 5: Environment Expansion

**Advanced purple team operations and strategic security development**

[under construction]

**Value Proposition**: _Know how to lead security operations and drive strategic improvements_

---


#### 📊 Phase Progression Summary

| Phase       | Focus Area                | Timeline             | Complexity |
| ----------- | ------------------------- | -------------------- | ---------- |
| **Phase 1** | Infrastructure Foundation | Nov-Dec 2025         | ⭐⭐         |
| **Phase 2** | Security Monitoring       | Dec <br>2025         | ⭐⭐⭐        |
| **Phase 3** | Vulnerability Analysis    | Dec-Jan<br>2025-2026 | ⭐⭐⭐⭐       |
| **Phase 4** | Offensive Operations      | Jan-Feb<br>2026      | ⭐⭐⭐⭐⭐      |
| **Phase 5** | Advanced Operations       | Ongoing              | ⭐⭐⭐⭐⭐      |


---


## Let's Connect

- **Email:** johnnymeintel@gmail.com
- **LinkedIn:** https://www.linkedin.com/in/johnny-meintel-3a9280269/
- **X:** x.com/54807463
- **Personal Website:** www.johnnymeintel.com (under construction)
- **Blog:** www.medium.com/@johnnymeintel


## More About Me

### Currently Reading

-  **Where Wizards Stay Up Late: The Origins Of The Internet** by *Katie Hafner*
- **This Is How They Tell Me the World Ends: The Cyberweapons Arms Race** by *Nicole Perlroth*

### Fun Facts

- I used to work as a fitness instructor and I competed in a bodybuilding contest in 2019.
- I play classical acoustic guitar.
- I believe anything can be made into a quesadilla, cheeseburger, or sandwich. 



*"The hope is that, in not too many years, human brains and computing machines will be coupled together very tightly, and that the resulting partnership will think as no human brain has ever thought and process data in a way not approached by the information-handling machines we know today."*

**- Licklider, J.C.R.**