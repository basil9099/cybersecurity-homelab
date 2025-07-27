# 🛡️ Splunk Enterprise – Windows Homelab Deployment
> Centralised logging + detection engineering for the Cybersecurity Homelab.

---

## 1. Lab Topology
| Host | Role | OS |
|------|------|----|
| `WIN-SPLUNK` | Splunk Enterprise 9.x | Windows Server 2022 |
| `WIN-DC01`   | AD DS / DNS / DHCP    | Windows Server 2022 |
| `WIN-WS01`   | Workstation + Sysmon  | Windows 10 Pro |
| `pfSense`    | Perimeter firewall    | pfSense CE 2.7 |

![diagram](img/splunk-overview.png)

---

## 2. Apps / Add-ons Installed
| App | Purpose |
|-----|---------|
| **Splunk App for Windows Infrastructure** | Dashboards for AD, DNS, DHCP, etc. |
| **Splunk Security Essentials (SSE)** | 120 + ATT&CK-mapped detections |
| **Splunk Common Information Model (CIM) Add-on** | Data-model normalisation |
| **Splunk App for Sysmon** | Visualises Sysmon Event ID 1–24 |

---

## 3. Data onboarding

### 3.1 Universal Forwarder (UF)

```powershell
msiexec /i splunkforwarder-9.x.x-x64-release.msi AGREETOLICENSE=Yes ^
  RECEIVING_INDEXER="WIN-SPLUNK:9997" WINEVENTLOG_SEC_ENABLE=1 ^
  WINEVENTLOG_SYS_ENABLE=1
