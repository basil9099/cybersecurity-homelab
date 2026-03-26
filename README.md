# Cybersecurity Homelab

> A practical, hands-on lab environment for simulating real-world attacks, building detection pipelines, and developing offensive and defensive security skills.

> [!NOTE]
> **Work in Progress** — This repository serves as a personal training ground for building technical cybersecurity skills with the goal of transitioning into a professional security role. Feedback, learning suggestions, and collaboration are always welcome.

---

## Table of Contents

- [Repository Structure](#repository-structure)
- [Offensive Security](#offensive-security)
- [Defensive Security](#defensive-security)
- [Hardware Pentesting](#hardware-pentesting)
- [Goals](#goals)
- [Links](#links)

---

## Repository Structure

```
cybersecurity-homelab/
├── projects/
│   ├── offensive/                        # Red team tools & exercises
│   │   ├── honeypot/                     # Mirage — Multi-protocol honeypot system
│   │   ├── vulnerability_scanner/        # SPECTRE — Network vulnerability scanner
│   │   ├── api_security_tester/          # Full-stack API security scanner (FastAPI + React)
│   │   ├── exploit_framework/            # Apex — Modular exploit framework
│   │   ├── brute_forcer/                 # Dictionary-based brute-force tools
│   │   ├── osint_framework/              # OSINT reconnaissance framework
│   │   ├── ad_enum/                      # Active Directory enumeration
│   │   ├── keylogger/                    # Educational USB keylogger
│   │   ├── vulnerable_web_app/           # BREACH — Custom CTF with OWASP Top 10 challenges
│   │   └── htb_writeups/                 # HackTheBox writeups & homelab exercises
│   │
│   ├── defensive/                        # Blue team tools & infrastructure
│   │   ├── network_baseline_monitor/     # SOC-grade network behavioral analysis
│   │   ├── anomaly_detector/             # ML-based anomalous login detection
│   │   ├── cloud_security_scanner/       # NIMBUS — Multi-cloud CSPM scanner
│   │   ├── metadata_stripper/            # Privacy-focused metadata removal
│   │   ├── attack_chain_correlator/      # AI-powered MITRE ATT&CK correlation
│   │   ├── siem_log_pipeline/            # SENTINEL — Log aggregation & visualization pipeline
│   │   ├── incident_response_engine/     # AEGIS — Automated IR playbook engine
│   │   ├── threat_intel_aggregator/      # WATCHTOWER — Threat intelligence feed aggregator
│   │   ├── splunk/                       # Splunk SIEM deployment & detection engineering
│   │   ├── pfsense_firewall/             # pfSense network segmentation & monitoring
│   │   ├── network_monitoring/           # Wireshark, Zeek, and Suricata labs
│   │   └── windows_server_with_AD/       # Active Directory setup with DNS, DHCP, GPOs
│   │
│   └── hardware/                         # Physical security tools
│       ├── ble_scanner/                  # PHANTOM — BLE security scanner
│       ├── flipper_zero/                 # Flipper Zero device exploitation
│       └── wifi_pineapple/               # WiFi Pineapple penetration testing
│
├── docs/                                 # Architecture diagrams
└── screenshots/                          # Visual documentation
```

---

## Offensive Security

### Tools & Frameworks

| Project | Description | Key Tech |
|---|---|---|
| **[Mirage](projects/offensive/honeypot/)** | Multi-protocol honeypot (SSH, HTTP, FTP, Telnet) with live dashboard | Paramiko, Rich |
| **[SPECTRE](projects/offensive/vulnerability_scanner/)** | Port scanning, banner grabbing, and CVE lookup | Nmap, NVD API |
| **[API Security Tester](projects/offensive/api_security_tester/)** | Full-stack scanner for rate limiting, auth bypass, SQLi, IDOR | FastAPI, React |
| **[Apex](projects/offensive/exploit_framework/)** | Modular exploit framework with payloads and session management | Python |
| **[Brute Forcer](projects/offensive/brute_forcer/)** | Dictionary attacks against DVWA and Juice Shop | Requests |
| **[OSINT Framework](projects/offensive/osint_framework/)** | Passive recon: WHOIS, DNS, crt.sh, Shodan, HIBP | Requests |
| **[AD Enum](projects/offensive/ad_enum/)** | LDAP-based Active Directory enumeration | ldap3 |
| **[BREACH](projects/offensive/vulnerable_web_app/)** | Custom CTF with 8 OWASP Top 10 challenge categories | FastAPI, Jinja2 |
| **[Keylogger](projects/offensive/keylogger/)** | Educational red team keylogger with screenshot capture | pynput, Pillow |

### HTB Writeups & Exercises

Documented walkthroughs for retired HackTheBox machines and original homelab exercises — see [htb_writeups/](projects/offensive/htb_writeups/).

| Machine | Difficulty | Key Vulnerabilities |
|---|---|---|
| Cap | Easy | IDOR, Linux capabilities abuse |
| Blue | Easy | MS17-010 (EternalBlue) |
| Optimum | Easy | HFS RCE + kernel privesc |
| Wifinetic | Easy | Anonymous FTP, WPS brute-force |

---

## Defensive Security

### Tools & Frameworks

| Project | Description | Key Tech |
|---|---|---|
| **[Network Baseline Monitor](projects/defensive/network_baseline_monitor/)** | Traffic baselining with statistical anomaly detection | Scapy, SciPy |
| **[Anomaly Detector](projects/defensive/anomaly_detector/)** | ML-based login anomaly detection | scikit-learn |
| **[NIMBUS](projects/defensive/cloud_security_scanner/)** | Multi-cloud CSPM with CIS benchmark compliance | boto3, Azure SDK |
| **[Metadata Stripper](projects/defensive/metadata_stripper/)** | EXIF/GPS/author metadata removal from files | Pillow, pikepdf |
| **[Attack Chain Correlator](projects/defensive/attack_chain_correlator/)** | MITRE ATT&CK kill chain correlation with Bayesian scoring | FastAPI, SQLite |
| **[SENTINEL](projects/defensive/siem_log_pipeline/)** | Log aggregation pipeline with unified dashboard | Rich, SQLite |
| **[AEGIS](projects/defensive/incident_response_engine/)** | Automated IR playbook engine mapped to NIST 800-61 | PyYAML, Rich |
| **[WATCHTOWER](projects/defensive/threat_intel_aggregator/)** | Threat intel feed aggregator with IOC correlation | Requests, aiohttp |

### Infrastructure Labs

| Lab | Description |
|---|---|
| **[Splunk](projects/defensive/splunk/)** | Windows SIEM with Sysmon, detection engineering, custom dashboards |
| **[pfSense](projects/defensive/pfsense_firewall/)** | Network perimeter with WAN/LAN segmentation and DHCP |
| **[Network Monitoring](projects/defensive/network_monitoring/)** | Wireshark, Zeek, and Suricata attack scenario labs |
| **[Windows Server + AD](projects/defensive/windows_server_with_AD/)** | Domain controller with Group Policies, DNS, DHCP |

---

## Hardware Pentesting

| Project | Description |
|---|---|
| **[PHANTOM](projects/hardware/ble_scanner/)** | BLE device discovery and security assessment with 10 automated checks |
| **[Flipper Zero](projects/hardware/flipper_zero/)** | RFID/NFC cloning, Sub-GHz replay, IR testing, BadUSB |
| **[WiFi Pineapple](projects/hardware/wifi_pineapple/)** | Rogue AP, packet sniffing, credential harvesting via GL.iNet router |

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

> [!NOTE]
> **AI Use Disclaimer** — Portions of this repository, including code, documentation, and configurations, may have been drafted or refined with the assistance of AI tools (e.g. Claude). All AI-generated content has been reviewed, tested, and validated by the repository author. AI assistance is used as a productivity and learning aid; it does not replace understanding of the underlying concepts, and any techniques or tools documented here are the result of hands-on experimentation in an isolated lab environment.
