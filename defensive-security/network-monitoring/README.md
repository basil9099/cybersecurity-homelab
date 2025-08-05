# 🛡️ Blue Team Exercise: Network Threat Detection with Wireshark

This project, located under [`defensive-security/network-monitoring`](https://github.com/basil9099/cybersecurity-homelab/tree/main/defensive-security/network-monitoring), demonstrates how to detect common network threats using Wireshark. The lab simulates several attack types and shows how to capture, analyze, and detect them using open-source tools.

## 🔧 Lab Setup

- **Attacker**: Kali Linux
- **Victim**: Ubuntu or Windows VM
- **Sniffer**: Wireshark or tcpdump on the same or a mirrored interface
- **Tools Used**: Nmap, Hydra, Wireshark, Suricata (optional)

## 📦 Scenarios Included

| Scenario | Description | Link |
|---------|-------------|------|
| Nmap Scan | Simulates active reconnaissance | [attack-scenarios/nmap-scan.md](attack-scenarios/nmap-scan.md) |
| Brute Force | Simulates SSH brute force login attempt | [attack-scenarios/brute-force.md](attack-scenarios/brute-force.md) |
| Malware Beaconing | Simulates periodic communication to an external server | [attack-scenarios/beaconing.md](attack-scenarios/beaconing.md) |

## 📁 Files

- `pcaps/`: Packet captures of each attack.
- `filters/`: Wireshark filters used for detection.
- `screenshots/`: Analysis visuals and explanations.
- `rules/`: Optional Suricata rule examples.

## 🧪 How to Use

1. Open `.pcapng` files in Wireshark.
2. Apply corresponding filter from `filters/`.
3. Compare traffic patterns and match against known indicators.
4. Review screenshots and notes for threat indicators.

## ✅ Example Filters

```wireshark
ip.addr == 192.168.1.5 && tcp.flags.syn == 1
http.request && ip.dst == 10.0.0.2
tcp.port == 22 && tcp.analysis.retransmission
```
