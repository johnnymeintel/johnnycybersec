# Phase Two - SIEM Implementation

> **Learning Focus**: Learn Splunk basics and ensure logs are forwarding before beginning adversary emulation.

---

## **Overview**

I kept Phase 2 simple. Get Splunk logs coming in, learn some basic SPL queries, create my first Splunk dashboard, and create some diagnostic scripts for future use. 

**Key Challenge**: Separating signal from noise. With Sysmon implemented, I have thousands of events per hour. This is good because I know the lab is working. It is challenging because as an analyst I can't spend all day tracking down potentially benign errors or warnings. My method for learning SPL for this phase was centered around identifying which events to rule out. 

---

## **Repository Structure**

```
Phase 2 - SIEM Implementation/
├── readme.md
│
├── Diagnostic Scripts/
│   ├── SIEM01_Splunk_Diagnostic.sh
│   └── Windows_Splunk_Diagnostic.ps1
│
└── Splunk Dashboard/
    ├── My First Splunk Dashboard.md
    │
    └── assets/
        ├── Dashboard1.png
        ├── Dashboard2.png
        ├── Dashboard3.png
        ├── Dashboard4.png
        ├── Dashboard5.png
        ├── Dashboard6.png
        ├── Dashboard7.png
        ├── Dashboard8.png
        └── Dashboard9.png
```

---

## **Key Milestones**

| Milestone            | Status   | Details                                                  |
| -------------------- | -------- | -------------------------------------------------------- |
| ✅ Basic Queries      | Complete | Sorting incoming events by hostname, sourcetype, etc.    |
| ✅ My First Dashboard | Complete | Homelab pulse - quick snapshot of everything             |
| ✅ Noise Reduction    | Complete | Identifying benign events to filter out of the dashboard |


---

## **Related Content**

### **Technical Articles**

- [Let's Learn How to Splunk](https://medium.com/@johnnymeintel/splunk-basics-homelab-soc-in-a-box-b7f0d2746fdc)
- [Noise Reduction - Part 1](https://medium.com/@johnnymeintel/splunk-homelab-noise-reduction-part-1-6a092164bbc0)

### **External Resources**

- [Splunk Free Training](https://www.splunk.com/en_us/training/free-courses/overview.html)
- [Windows Event Appendix](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)