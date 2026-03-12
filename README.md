# 🛡️ SOC Homelab: Build a security operations center in a secure and virtual environment for log analysis and real-time threat monitoring and response

> Hands-on SOC Analyst portfolio: Wazuh SIEM deployment in an Active Directory environment, real-world attack simulation, and incident response documentation.

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/) [![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.9-blue)](https://wazuh.com/) [![Active Directory](https://img.shields.io/badge/Environment-Active%20Directory-green)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/) [![Sysmon](https://img.shields.io/badge/EDR-Sysmon-blue)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) [![pfSense](https://img.shields.io/badge/Firewall-pfSense-darkblue)](https://www.pfsense.org/) [![Status](https://img.shields.io/badge/Status-In%20Progress-orange)](.)[![License](https://img.shields.io/badge/License-Educational-yellow)](.)

<img width="1108" height="729" alt="image" src="https://github.com/user-attachments/assets/6eee0697-abe4-4291-9b6d-945c9ffb9784" />

Cybersecurity relies on two main objectives:
1. Cyberattack prevention
2. Cyberattack detection and response

To achieve these goals, organizations increasingly deploy in-house Security Operations Centers (SOCs), responsible for IT infrastructure threat monitoring and security incident response.

This project demonstrates how to build your own SOC homelab — a downsized version obvioulsy — in a virtual environment with limited resources. The objectives are to practice critical IT security concepts such as network segmentation, centralized threat detection, and incident response workflows, while gaining hands-on experience integrating cybersecurity tools, simulating attacks, and detecting attack patterns in real time.
## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Technologies Used](#3-technologies-used)
4. [Attack Scenarios](#4-attack-scenarios)
   - [Scenario 1 — RDP Bruteforce](#41-rdp-bruteforce-attack)
   - [Scenario 2 — Mimikatz & Credential Dumping](#42-mimikatz--credential-dumping)
   - [Scenario 3 — Kerberoasting Attack](#43-kerberoasting-attack)
5. [Conclusion & Next Steps](#5-conclusion--next-steps)
6. [Resources](#6-resources)
   
## 🎯1. Project Overview

This homelab replicates a Security Operations Center environment, designed to practice blue team detection and incident response in attack scenarios context.

### 1.1 Architecture at a Glance

The lab consists of **three isolated network zones** managed by a central firewall:

<img width="1033" height="727" alt="image" src="https://github.com/user-attachments/assets/01334613-7a2d-4c2d-9315-306e9a6fc365" />

| Zone                    | Purpose                          | Key Components                                             |
| ----------------------- | -------------------------------- | ---------------------------------------------------------- |
| **🔴 WAN/External**     | Threat source                    | Kali Linux (bruteforce, exploitation, recon)               |
| **🔵 Active Directory** | Corporate environment simulation | Domain Controller, Windows workstations, Sysmon monitoring |
| **🔶 SOC/SIEM**         | Centralized security monitoring  | Wazuh Manager, Indexer, Dashboard (all-in-one SIEM stack)  |
| **🟪 DMZ**              | Exposed services (future)        | Planned: DVWA, SSH honeypot                                |

**Network segmentation** is strictly enforced through pfSense firewall rules, blocking lateral movement between zones while allowing legitimate flows (logs to SOC, internet access from AD). This creates realistic security boundaries found in enterprise environments.

### 1.2 Learning Objectives

This project serves as a **practical training ground** for SOC Analyst skills:

**🔍 Log Analysis & Correlation**
- Aggregate events from multiple sources (Windows Security, Sysmon, pfSense syslog)
- Correlate isolated events into attack patterns (e.g., 5 failed logins → bruteforce alert)
- Distinguish false positives from genuine threats

**🎯 Threat Detection Engineering**
- Deploy and customize SIEM detection rules (Wazuh built-in + custom)
- Map detections to MITRE ATT&CK framework (T1110, T1003.001, etc.)
- Tune alert thresholds to reduce noise

**🛡️ Incident Response Workflow**
- Identify Indicators of Compromise (IoCs) from alerts
- Trace attack kill chains from initial access to post-exploitation
- Document containment and remediation steps

**⚔️ Understanding the Adversary**
- Simulate realistic attack scenarios (RDP bruteforce, credential dumping)
- Learn common adversary TTPs (Tactics, Techniques, Procedures)
- Practice defensive countermeasures

### 1.3 Why am I even doing this?

This homelab was built as part of my career transition into cybersecurity. I'm currently completing a one-year bachelor program in systems and network security while actively seeking my first SOC Analyst position or internship. This project has two main objectives: gaining hands-on experience with the tools and technologies used daily by security professionals, and demonstrating my technical skills and commitment through detailed documentation. I learn best by doing — setting up infrastructure, running attack simulations, analyzing logs - and writing about what I discover along the way.

---

## 🌐2. Architecture

This lab is built around a strictly segmented network architecture, designed to simulate a realistic enterprise environment. Each zone serves a dedicated purpose and communicates with others only through explicitly defined firewall rules enforced by a central perimeter firewall.

<img width="1091" height="928" alt="image" src="https://github.com/user-attachments/assets/108fda65-5fa7-4771-955f-4347606446aa" />

---

### 2.1 🔴WAN Zone (Simulated Internet)

**Role:** Represents the outside world — the Internet and its threats.

| Machine      | OS         | IP (Bridged) | Role                           |
| ------------ | ---------- | ------------ | ------------------------------ |
| **KALI-ATK** | Kali Linux | 10.2.5.150   | Simulates an external attacker |

**Configuration :**
- connected in **Bridged mode**, meaning it receives an IP on the physical host network and behaves like a machine external to the lab
- ensures that its IP address appears as a genuine external source in firewall and SIEM logs
- must traverse the pfSense WAN interface to reach any internal zone

**Used for:** port scanning, RDP bruteforce, and post-exploitation scenarios.

---

### 2.2 🔥Perimeter Zone – pfSense Firewall

**Role:** First line of defense. Enforces traffic filtering between all zones and acts as the lab's central router.

| Interfaces  | Network        | IP Address  | Description                           |
| ----------- | -------------- | ----------- | ------------------------------------- |
| **WAN**     | 10.2.5.0/24    | 10.2.5.100  | Internet-facing (bridged to host NIC) |
| **AD LAN**  | 10.0.10.0/24   | 10.0.10.1   | Active Directory zone                 |
| **SOC LAN** | 10.0.20.0/24   | 10.0.20.1   | SOC/SIEM zone                         |
| **DMZ**     | 172.16.30.0/24 | 172.16.30.1 | DMZ zone (exposed services)           |

**Security principle:** _Default deny — traffic is blocked unless explicitly permitted.

#### 🛡️Firewall Rules

🔵**AD LAN interface:**

| #   | Source       | Destination    | Protocol/Port | Action  | Purpose                             |
| --- | ------------ | -------------- | ------------- | ------- | ----------------------------------- |
| 1   | 10.0.10.0/24 | 10.0.20.10     | TCP 1514      | ✅ Allow | Wazuh agent log forwarding to SIEM  |
| 2   | 10.0.10.0/24 | any            | TCP 80, 443   | ✅ Allow | Outbound web access for AD machines |
| 3   | 10.0.10.0/24 | any            | UDP/TCP 53    | ✅ Allow | DNS resolution                      |
| 4   | 10.0.10.0/24 | 172.16.30.0/24 | any           | ❌ Block | Isolate AD users from DMZ           |
| 5   | any          | any            | any           | ❌ Block | Implicit defaul                     |

🔶**SOC LAN interface:**

| #   | Source       | Destination    | Protocol/Port | Action  | Purpose                               |
| --- | ------------ | -------------- | ------------- | ------- | ------------------------------------- |
| 1   | 10.0.20.0/24 | any            | TCP 80, 443   | ✅ Allow | SIEM outbound (updates, threat intel) |
| 2   | 10.0.20.0/24 | 10.0.10.10     | UDP/TCP 53    | ✅ Allow | DNS resolution                        |
| 3   | 10.0.20.0/24 | 172.16.30.0/24 | any           | ❌ Block | Isolate SIEM from DMZ                 |
| 4   | any          | any            | any           | ❌ Block | Implicit default deny                 |

🟪**DMZ interface:**

| #   | Source | Destination | Protocol/Port | Action | Purpose |
| --- | ------ | ----------- | ------------- | ------ | ------- |
| 1   | WIP    | WIP         | WIP           | WIP    | WIP     |

**Additional capabilities:**
- Syslog forwarding to Wazuh (firewall events → SIEM)
- NAT/PAT for controlled service exposure during attack scenarios

---

### 2.3 🔵Active Directory Zone (10.0.10.0/24)

**Role:** Simulates an organization's internal environment with centralized authentication and endpoint management.

| Machine   | OS                    | Role                      | RAM | IP         |
| --------- | --------------------- | ------------------------- | --- | ---------- |
| **DC01**  | Windows Server 2022   | Domain Controller         | 2GB | 10.0.10.10 |
| **WKS01** | Windows 10 Enterprise | Domain-joined workstation | 2GB | 10.0.10.15 |

**Services running:**
- Active Directory Domain Services (`netwatch.local`)
- Internal DNS (DC01 acts as authoritative DNS server for the domain)
- Group Policy Objects — password policy, logon auditing, object access auditing
- Sysmon deployed on all Windows machines for advanced telemetry

**Active Directory Domain:** `netwatch.local`

<img width="405" height="359" alt="image" src="https://github.com/user-attachments/assets/21209903-e431-4961-8e20-23c7e9b8fe3e" />

|    Users     |                  User Logon                  |  Function  | Security Group     |
| :----------: | :------------------------------------------: | :--------: | ------------------ |
|  James Park  |   j.park@netwatch.local<br>NETWATCH\j.park   |  Finance   | Finance Department |
| Marcus Chen  |   m.chen@netwatch.local<br>NETWATCH\m.chen   |     HR     | HR Department      |
| David Torres | d.torres@netwatch.local<br>NETWATCH\d.torres |     IT     | IT Department      |
| Sarah Volkov | s.volkov@netwatch.local<br>NETWATCH\s.volkov |     IT     | IT Department      |
| Alex Ivanov  | a.ivanov@netwatch.local<br>NETWATCH\a.ivanov |   Sales    | Sales Department   |
|  Lisa Ross   |   l.ross@netwatch.local<br>NETWATCH\l.ross   | Management | Management         |

**Security monitoring configured:**
- Event 4625 — failed authentication attempts
- Event 4624 — successful logon
- Sysmon Event 10 — LSASS memory access (Mimikatz detection)
- Wazuh agents installed on DC01 and WKS01

**Attack surface:** RDP bruteforce target, post-exploitation credential dumping, lateral movement simulation.

---

### 2.4 🔶SOC Zone (10.0.20.0/24)

**Role:** Core monitoring and detection layer. Centralizes log collection, event correlation, and alerting across the entire lab.

| Machine    | OS               | Role             | RAM | IP         |
| ---------- | ---------------- | ---------------- | --- | ---------- |
| **SIEM01** | Ubuntu 22.04 LTS | Wazuh All-in-One | 4GB | 10.0.20.10 |

**Stack deployed:**
- **Wazuh Manager** — log collection, rule engine, and event correlation
- **Wazuh Indexer** — log storage and search (based on OpenSearch)
- **Wazuh Dashboard** — visualization and alerting interface (based on OpenSearch Dashboards)

**Log sources integrated:**
- Wazuh agents (DC01, WKS01)
- pfSense syslog (firewall block/allow events)
- Windows Security Event Logs (4624, 4625)
- Sysmon telemetry (Event IDs 1, 3, 10)

**Capabilities:**
- Real-time detection of malicious activity
- Cross-source event correlation

---

### 2.5 🟪DMZ (172.16.30.0/24) 

**Role:** Semi-exposed zone intended to host services reachable from the simulated Internet.

**Statut :** 🚧 *Work In Progress*

**Planned:**
- Vulnerable web server (DVWA or Metasploitable)
- SSH honeypot for bruteforce detection

The DMZ is strictly isolated from both the AD and SOC zones — compromise of a DMZ service cannot directly pivot into internal infrastructure without traversing pfSense.

---

### 2.6 🔐Traffic Flow Summary

| Flow                                     | Status                 | Notes                              |
| ---------------------------------------- | ---------------------- | ---------------------------------- |
| AD → SOC (TCP 1514)                      | ✅ Allowed              | Wazuh agent log forwarding         |
| AD → Internet (80, 443, 53)              | ✅ Allowed              | User web access                    |
| SOC → Internet (80, 443, 53)             | ✅ Allowed              | Updates & packages                 |
| WAN → AD (TCP 3389, NAT/PORT FORWARDING) | ✅ Allowed (controlled) | Attack scenarios only              |
| AD ↔ DMZ                                 | ❌ Blocked              | Prevent lateral movement from DMZ  |
| SOC ↔ DMZ                                | ❌ Blocked              | SIEM isolation                     |

---

## 💻3. Technologies Used

### 3.1 Virtualisation & Infrastructure

| Component           | Technology             | Version | Role                                                      |
| ------------------- | ---------------------- | ------- | --------------------------------------------------------- |
| **Hypervisor**      | VMware Workstation Pro | 17      | Type-2 virtualisation, network isolation via LAN segments |
| **Firewall/Router** | pfSense                | 2.8     | Network segmentation, stateful packet filtering           |

---

### 3.2 Operating Systems

| OS                        | Version   | Usage                                | Justification                                                         |
| ------------------------- | --------- | ------------------------------------ | --------------------------------------------------------------------- |
| **Windows Server**        | 2022      | Domain Controller (AD DS, DNS, GPOs) | Industry-standard corporate environment                               |
| **Windows 10 Enterprise** | 22H2      | Domain-joined workstation            | Realistic endpoint attack target                                      |
| **Ubuntu Server**         | 24.04 LTS | Wazuh SIEM stack                     | Official Wazuh support, lightweight (~500MB RAM idle), LTS until 2029 |
| **Kali Linux**            | 2025.3    | Attack machine                       | Pre-configured offensive toolset (Hydra, Mimikatz, etc.)              |

---

### 3.3 Security Stack

| Component               | Technology  | Version | Role                                                                  |
| ----------------------- | ----------- | ------- | --------------------------------------------------------------------- |
| **SIEM**                | Wazuh       | 4.14    | Log collection, event correlation, real-time alerting                 |
| **Endpoint Monitoring** | Sysmon      | 15.15   | Advanced Windows telemetry (process, network, registry, LSASS access) |
| **Wazuh Agent**         | Wazuh Agent | 4.14    | Lightweight collector deployed on endpoints (DC01, WKS01)             |

#### Why Wazuh?

Wazuh hits the right balance for a homelab context: it's open-source and free, ships with a native MITRE ATT&CK-mapped ruleset, integrates cleanly with Active Directory and Sysmon without custom parsers, and runs a lightweight agent that doesn't meaningfully impact endpoint performance.

**Reasons for choosing Wazuh:**
- ✅ **Open-source, free, and enterprise-grade** (vs. paid Splunk Enterprise)
- ✅ **Native MITRE ATT&CK mapping** (built-in rules for T1110, T1003.001)
- ✅ **Out-of-the-box AD + Sysmon integration**
- ✅ **Lightweight agent** (<50MB RAM per endpoint)
- ✅ **Comprehensive documentation** and active community

**Alternatives considered:** Splunk, Elastic Stack (ELK), Graylog

#### How it works ?

Agents installed on Windows endpoints (DC01, WKS01) collect Windows Event Logs and Sysmon telemetry and forward them to the Wazuh Manager over TCP 1514. pfSense ships its firewall logs directly to the Manager via syslog (UDP 514). The Manager runs the rule engine — parsing, decoding, and correlating incoming events against both built-in and custom rulesets to generate alerts. Alerts and raw logs are then indexed in the Wazuh Indexer (OpenSearch) for storage and search, and surfaced through the Wazuh Dashboard for visualization and investigation.

1. **Endpoints** → Wazuh Agent → Manager (TCP 1514)
2. **pfSense** → Syslog → Manager (UDP 514)
3. **Manager** → Indexer (storage & search engine)
4. **Dashboard** → Indexer (queries)

<img width="1385" height="738" alt="image" src="https://github.com/user-attachments/assets/5da64d98-fe33-4dad-bb05-c9e62bab21f1" />

#### What does Sysmon bring to the table ?

Windows Security Event Logs provide authentication and access events, but they say nothing about what's actually happening at the process level — which executable ran, what it connected to, or whether it tried to access sensitive memory. Sysmon fills that gap and is feeding enriched telemetry directly into Wazuh.

**Sysmon addresses all of these:**
- ✅ **Event ID 1** — Process Creation (full command-line logging)
- ✅ **Event ID 3** — Network Connection (which process contacts which IP)
- ✅ **Event ID 10** — Process Access (**critical for Mimikatz detection** → LSASS access)
- ✅ **Event ID 13** — Registry modifications (persistence detection)
- ✅ **SwiftOnSecurity config** — community-approved ruleset, well-balanced signal-to-noise ratio

---

## 🔫4. Attack Scenarios

This section documents a series of attack scenarios executed against the lab environment, following a realistic kill chain from initial access to lateral movement. Each scenario is approached from both sides — the attacker's perspective (tools, commands, objectives) and the defender's perspective (detection, IOC collection, incident response) — to reflect the dual awareness expected of a SOC analyst.

Each scenario follows the same structure:

> **Attack Description** → **Why It Matters** → **Lab Context** → **Reconnaissance** → **Attack Execution** → **Detection** → **IOC Collection** → **Incident Response** → **Remediation** → **Conclusion**

Scenarios are designed to chain into each other — the access gained in Scenario 1 is the prerequisite for Scenario 2, and so on. MITRE ATT&CK technique IDs are mapped throughout, from detection rules to remediation recommendations.

| Scenario                                   | MITRE ATT&CK | Status         |
| ------------------------------------------ | ------------ | -------------- |
| Scenario 1 — RDP Bruteforce attack         | T1110.001    | ✅ Done         |
| Scenario 2 — Mimikatz / Credential Dumping | T1003.001    | 🔄 In progress |
| Scenario 3 — Kerberoasting                 | T1558.003    | 📋 Planned     |

---

### 4.1 RDP Bruteforce Attack

**📁 [Complete documentation](https://github.com/d4yon/soc-homelab-ad-attack-and-detection/blob/main/attack-scenarios/RDP_bruteforce.md)**

#### Summary
An external attacker discovers an RDP endpoint exposed on the WAN interface via NAT port forwarding and launches a dictionary attack against a domain user account. The scenario is demonstrated twice. Once without an account lockout policy (bruteforce succeeds, RDP session opened) and with one enforced (account locked after 5 attempts, attacker blocked).

#### Detection
- **Windows Events:** 4625 (Failed Logon), 4624 (Successful Logon), 4740 (Account Lockout)
- **Wazuh:** Built-in rules 60122, 60204 + custom rules 100010 (bruteforce), 100011 (lockout)
- **IOCs:** Source IP 10.2.5.150 (KALI-ATK) · Target account d.torres · LogonType 3 (Network)

#### Key Screenshot

<img width="1918" height="884" alt="image" src="https://github.com/user-attachments/assets/2265ac80-34c1-4d36-9f19-73bff8ad3c71" />

---

### 4.2 Mimikatz & Credential Dumping

> 🚧 **Work in Progress** — This scenario is currently being executed and documented.
> 
> **MITRE:** T1003.001 · **Status:** 🔄 In progress

---

### 4.3 Kerberoasting Attack

> 🚧 **Work in Progress** — This scenario will be documented upon completion of Scenario 2.
>
> **MITRE:** T1550.002 · **Status:** 📋 Planned

---

## 5.🏁 Conclusion & Next Steps

*This section will be completed once all attack scenarios are documented.*

| Scenario                                   | MITRE ATT&CK | Status         |
| ------------------------------------------ | ------------ | -------------- |
| Scenario 1 — RDP Bruteforce attack         | T1110.001    | ✅ Done         |
| Scenario 2 — Mimikatz / Credential Dumping | T1003.001    | 🔄 In progress |
| Scenario 3 — Kerberoasting                 | T1558.003    | 📋 Planned     |

Potential extensions: DCSync · Web Application attacks (DVVA) · IDS/IPS integration · Response Automation (SOAR) · Honeypot

---

## 6.🔗 Resources

**Official documentation**
- [Wazuh](https://documentation.wazuh.com/) · [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) · [MITRE ATT&CK](https://attack.mitre.org/) · [pfSense](https://docs.netgate.com/) · [NetExec Wiki](https://www.netexec.wiki/)

**Configurations**
- [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config) · [Wazuh Ruleset](https://github.com/wazuh/wazuh-ruleset) 

**References**
- [Kaspersky — RDP attacks surge 2020](https://www.kaspersky.com/about/press-releases/the-great-migration-of-cyberthreats-attacks-on-remote-desktop-protocols-grew-by-242-reaching-33-billion-in-2020)
- [AD Attack & Defense Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
- [Detecting Mimikatz with Sysmon](https://0x2asecurity.com/siem-engineering/2025/from-attacker-to-defender-testing-sysmon-against-mimikatz-procdump-and-powershell/)
- [Kerberoasting Detection](https://adsecurity.org/?p=3458)
- [Building a SOC homelab](https://pratik-it.com/soc-homelab-concevoir-un-centre-operationnel-de-securite-en-environnement-virtualise/#1_Les_fondements_du_projet)

---

## 👤 About

**Wassim Mbarki**  
Bachelor student in Systems & Network Security · Aspiring SOC Analyst

📧 [email](mailto:wassim.mbarki@condorcet.be) · 💼 [LinkedIn](https://www.linkedin.com/in/wassim-mbarki-922a0513a/) · 🐙 [GitHub](https://github.com/repos?q=owner%3A%40me)

*Last updated: 12.03.26*
