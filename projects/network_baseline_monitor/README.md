# Network Baseline Monitor

> Establish normal traffic behavior baselines, detect statistical deviations, and generate anomaly reports — demonstrating SOC-grade network behavioral analysis techniques.

> **Disclaimer:** This tool is for educational purposes and authorized network monitoring only. Only capture and analyse traffic on networks you own or have explicit written permission to monitor. Unauthorized packet capture is illegal in most jurisdictions.

---

## What It Does

| Feature | Description |
|---|---|
| **Traffic Collection** | Packet capture via Scapy (live) or PCAP file analysis (offline) |
| **Window Aggregation** | Summarises traffic into configurable time windows (bytes, packets, top-talkers, port counts, protocol distribution) |
| **Baseline Establishment** | Computes mean, std, P25/P75 per metric per (hour-of-day, day-of-week) slot |
| **Statistical Detection** | Z-score, IQR fence, and moving-average comparison against baselines |
| **Port Scan Detection** | Flags sources contacting >20 unique ports in one window |
| **Exfiltration Detection** | Flags external outbound bytes exceeding 5× baseline mean |
| **C2 Beaconing Detection** | Identifies periodic connections (low coefficient of variation) |
| **Lateral Movement Detection** | Flags new internal east-west communication pairs |
| **Alert Engine** | Graduated severity (low/medium/high), suppression, coordinated incident detection |
| **Reports** | Colorized ASCII dashboard, standalone HTML report, JSON export |
| **Demo Mode** | Self-contained demo with synthetic data — no root or live traffic required |

---

## Requirements

```bash
pip install -r requirements.txt
```

Dependencies: `scapy>=2.5`, `pandas>=2.0`, `scipy>=1.11`, `colorama>=0.4`, `jinja2>=3.1`

> **Note:** Live packet capture requires root (`sudo`) on Linux/macOS. All other modes (PCAP analysis, demo, reporting) run without elevated privileges.

---

## Usage

### Quick Demo (no root required)

```bash
python main.py demo
```

Generates 14 days of synthetic baseline traffic, injects 5 known attack scenarios (port scan, exfiltration, volume surge, lateral movement, ICMP flood), runs the full detection pipeline, and produces an HTML report in `/tmp/`.

### Live Traffic Collection (root required)

```bash
# Collect 60 one-minute windows from eth0
sudo python main.py collect -i eth0 --db net.db --count 60 --window 60

# Collect indefinitely (Ctrl+C to stop)
sudo python main.py collect -i eth0 --db net.db
```

### Offline PCAP Analysis

```bash
python main.py collect --pcap capture.pcap --db net.db
```

### Compute Baseline Profiles

```bash
# After collecting at least a few days of windows
python main.py baseline --db net.db

# Lower threshold for testing
python main.py baseline --db net.db --min-samples 10
```

### Real-Time Monitoring

```bash
sudo python main.py monitor -i eth0 --db net.db

# Tune alert thresholds
sudo python main.py monitor -i eth0 --db net.db \
  --threshold-medium 3.5 --threshold-high 6.0 \
  --suppress-window 30
```

### Generate Reports

```bash
# HTML report (default)
python main.py report --db net.db -o ./reports/

# Both HTML and JSON
python main.py report --db net.db --format both -o ./reports/
```

### Options Reference

| Flag | Command | Default | Description |
|---|---|---|---|
| `--interface / -i` | collect, monitor | auto-detect | Network interface |
| `--pcap` | collect | — | Read from PCAP file |
| `--db` | all | `network_baseline.db` | SQLite database path |
| `--window` | collect, monitor | `60` | Aggregation window in seconds |
| `--count` | collect | `0` (infinite) | Number of windows to capture |
| `--min-samples` | baseline | `30` | Min windows per time slot for baseline |
| `--threshold-medium` | monitor | `4.0` | Composite score for medium alert |
| `--threshold-high` | monitor | `7.0` | Composite score for high alert |
| `--suppress-window` | monitor | `15` | Alert suppression window (minutes) |
| `--format` | report, demo | `html` | `html` \| `json` \| `both` |
| `--output / -o` | report, demo | `.` or `/tmp` | Output directory for reports |

---

## Example Output

```
================================================================================
  NETWORK BASELINE MONITOR — Traffic Dashboard
================================================================================
  Timestamp            Packets    Bytes      Ext Out KB   Src IPs      Dst IPs
  ---------------------------------------------------------------------------
  03-19 14:00:00       187        2.3 MB     12.4         8            14
  03-19 14:01:00       203        2.6 MB     15.1         9            16
  03-19 14:02:00       2150       28.4 MB    51200.0      12           8        ← ANOMALY
  03-19 14:03:00       198        2.4 MB     11.9         8            13

  Recent Alerts:
  ---------------------------------------------------------------------------
  [14:02:00] HIGH   EXFILTRATION              score=8.4  src=10.0.0.12
  [14:02:00] HIGH   STATISTICAL_ANOMALY       score=7.1  src=statistical
```

---

## Architecture

```
network_baseline_monitor/
├── main.py                  # CLI entry point (collect / baseline / monitor / report / demo)
├── requirements.txt
├── collector/
│   ├── sniffer.py           # Scapy packet capture and PCAP reading
│   └── aggregator.py        # Per-window traffic statistics (TrafficWindow dataclass)
├── baseline/
│   ├── storage.py           # SQLite time-series database (windows, baselines, alerts)
│   └── profiler.py          # Baseline computation: mean, std, P25/P75 per time slot
├── detector/
│   └── statistical.py       # Z-score, IQR, moving-average scoring
├── analyzer/
│   └── patterns.py          # Port scan, exfiltration, C2 beaconing, lateral movement
├── alerts/
│   └── engine.py            # Alert scoring, severity levels, suppression, correlation
└── reports/
    └── generator.py         # ASCII dashboard, HTML report, JSON export
```

### Data Flow

```
Packets (live / PCAP)
        │
        ▼
   collector/sniffer.py     ← raw RawPacket list
        │
        ▼
   collector/aggregator.py  ← TrafficWindow (per-minute stats)
        │
        ▼
   baseline/storage.py      ← SQLite traffic_stats table
        │
    ┌───┴──────────────────────────┐
    ▼                              ▼
baseline/profiler.py        detector/statistical.py
(one-time baseline build)   (WindowScores: composite 0–10)
                                   │
                            analyzer/patterns.py
                            (AnomalyEvent list)
                                   │
                            alerts/engine.py
                            (Alert: low/medium/high)
                                   │
                            reports/generator.py
                            (HTML / JSON / ASCII)
```

---

## Design Notes

### Baseline Establishment Methodology

Baselines are computed per **(hour_of_day × day_of_week)** slot (168 unique slots). This captures both intraday variation (business hours vs. night) and weekly patterns (weekdays vs. weekends). Each slot requires a minimum number of samples (`--min-samples`, default 30) before it is marked ready — this prevents a single unusual observation from poisoning the baseline.

**Recommended collection period:** 2–4 weeks minimum, covering all 168 time slots with at least 30 samples each. For production environments, 3–6 months provides enough data to capture monthly patterns.

### Statistical Detection Methods

Three complementary methods are applied to each metric:

| Method | Trigger | Strength |
|---|---|---|
| **Z-score** | `abs((value - mean) / std) > 3.0` | Sensitive to extreme outliers |
| **IQR fence** | `value < Q1 - 1.5×IQR` or `value > Q3 + 1.5×IQR` | Robust to non-normal distributions |
| **Moving average** | `value / rolling_mean > 2.0` | Detects gradual trends |

A composite score (0–10) is computed as a weighted average of per-metric scores, with higher weights for security-sensitive metrics (`external_bytes_out` 25%, `total_bytes` 20%).

### Alert Levels

| Score | Level | Action |
|---|---|---|
| 1.0–3.9 | `low` | Write to database only |
| 4.0–6.9 | `medium` | Console warning + database |
| 7.0–10.0 | `high` | Bold red console escalation + database |
| Any (≥3 types simultaneously) | `coordinated_incident` | High-priority escalation |

**Alert suppression:** The same `(anomaly_type, src_ip)` pair will not generate duplicate console alerts within the suppression window (default 15 minutes), preventing analyst fatigue while still logging all events.

---

## Limitations

- **Baseline establishment time:** Meaningful baselines require weeks of data. The first days/weeks will produce many false positives.
- **New legitimate services:** When new applications are deployed, they may trigger exfiltration or volume alerts until incorporated into the baseline. Re-run `baseline` after deployment periods.
- **Encrypted traffic:** TLS/HTTPS content is opaque — this tool analyses volume and flow metadata, not payload content.
- **High-volume networks:** Raw packet capture with Scapy is not optimised for >1 Gbps links. Use NetFlow/IPFIX collection at scale.
- **IPv6:** Current implementation focuses on IPv4. IPv6 traffic is classified as "Other" protocol.
- **NAT environments:** Devices behind NAT appear as a single IP, reducing per-host granularity.

---

## Lab Integration

This tool integrates with the broader homelab defensive security stack:

| Integration | How |
|---|---|
| **Wireshark** | Export suspicious traffic from `network_baseline.db` alerts as PCAP for deep inspection |
| **Splunk** | Ingest `network_baseline_report.json` as a log source for correlation with Windows Event Logs and Sysmon data |
| **pfSense** | Enable NetFlow export; use `nfdump` to pre-aggregate flows before feeding into the collection pipeline |
| **Anomaly Detector** | Complements the ML-based Splunk log analyser with network-layer visibility |

### Incident Investigation Procedure

When an alert fires:
1. Note the `timestamp`, `anomaly_type`, `src_ip`, and `score` from the alert log
2. Run `python main.py report` to get the full context around that time window
3. Cross-reference the `src_ip` against DHCP leases and Active Directory to identify the host
4. For exfiltration alerts: check `top_destinations` in the alert detail; query threat intelligence (VirusTotal, Shodan) for the external IP
5. For port scan alerts: check whether the source is an authorized vulnerability scanner or a compromised host
6. For beaconing alerts: correlate the beacon interval with known C2 frameworks (Cobalt Strike default is 60s, Metasploit is irregular)
7. Isolate suspected hosts from the network for forensic imaging if the investigation confirms malicious activity

---

## Comparison to Commercial Solutions

| Feature | This Tool | Commercial NBA (e.g. Darktrace, ExtraHop) |
|---|---|---|
| Baseline methodology | Hour+day-of-week statistical profiles | ML models with unsupervised learning |
| Detection techniques | Z-score, IQR, moving average, pattern rules | Deep learning, peer-group analysis |
| Traffic visibility | Flow metadata + protocol distribution | Full packet decode, application layer |
| Scale | Single host / small lab | Enterprise 10+ Gbps |
| Cost | Free / open source | $100K+ per year |
| Customisation | Full source access | Limited rule customisation |

This implementation demonstrates the *principles* that commercial network detection and response (NDR) products build upon, making it valuable for understanding how these tools work and for validating detection logic in a controlled lab environment.
