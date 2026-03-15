# Cybersecurity Homelab

> A practical, hands-on lab environment for simulating real-world attacks, building detection pipelines, and developing offensive and defensive security skills.

> [!NOTE]
> **Work in Progress** — This repository serves as a personal training ground for building technical cybersecurity skills with the goal of transitioning into a professional security role. Feedback, learning suggestions, and collaboration are always welcome.

---

## Table of Contents

- [Repository Structure](#repository-structure)
- [Offensive Security Labs](#offensive-security-labs)
- [Defensive Security Labs](#defensive-security-labs)
- [Automation Projects](#automation-projects)
- [Goals](#goals)
- [Links](#links)

---

## Repository Structure

```
cybersecurity-homelab/
├── projects/
│   ├── honeypot/               # Lightweight TCP honeypot for trap-based detection
│   └── anomaly-detector/       # Python ML script for anomaly detection on logs
├── offensive-security/         # Exploits, payloads, and enumeration labs
├── defensive-security/
│   ├── splunk/                 # Splunk configuration, dashboards, and detection engineering
│   ├── pfsense-firewall/       # pfSense setup, network segmentation, and traffic monitoring
│   ├── network-monitoring/     # Wireshark, Zeek, and Suricata labs
│   └── windows-server-with-AD/ # Active Directory setup with DNS, DHCP, and GPOs
├── hardware-pentesting/        # Physical device exploitation (Flipper Zero, USB attacks)
├── docs/                       # Diagrams and architecture notes
├── tools/                      # Helper scripts and utilities
└── troubleshooting/            # Notes, fixes, and debugging steps for common lab issues
```

---

## Offensive Security Labs

Hands-on red teaming scenarios covering the full attack lifecycle:

| Category | Tools & Techniques |
|---|---|
| **Enumeration** | SMB, LDAP, DNS, web recon with Nmap, Nikto |
| **Exploitation** | Metasploit, manual RCEs, reverse shells |
| **Privilege Escalation** | Linux and Windows via kernel exploits and misconfigurations |
| **Web Attacks** | SQLi, XSS, IDOR, command injection with Burp Suite, SQLMap |
| **Network Analysis** | Traffic capture and analysis with Wireshark |

---

## Defensive Security Labs

Blue team capabilities developed to complement offensive skills:

| Category | Tools & Techniques |
|---|---|
| **Network Monitoring** | Wireshark, Zeek, Suricata for deep packet inspection |
| **Endpoint Protection** | Sysmon configuration, AV/EDR testing |
| **SIEM** | Splunk, Wazuh, ELK stack setup and tuning |
| **Threat Hunting** | Sigma rules, YARA signatures, HELK |
| **Detection Engineering** | Custom SPL queries and alerting rules |

---

## Automation Projects

| Project | Description |
|---|---|
| **Anomaly Detection Script** | Python + scikit-learn for statistical log analysis |
| **TCP Honeypot** | Listens on port 8080 with structured connection logging |
| **Splunk Integration** | Offline analysis pipeline using Splunk log exports |

---

## Goals

- Document CTF-style exercises and real-world security scenarios
- Build and maintain custom tools and scripts developed during engagements
- Create a living portfolio of practical, hands-on cybersecurity experience

---

## Links

- [Hack The Box Profile](https://app.hackthebox.com/profile/basil9099)
- [LinkedIn](https://www.linkedin.com/in/angus-dawson-92b035249)

---

> **Disclaimer:** All systems are hosted internally in an isolated lab environment. This repository is intended for educational and training purposes only.
