# SENTINEL

**Lightweight SIEM Log Pipeline for Cybersecurity Homelabs**

SENTINEL aggregates, normalizes, stores, and visualizes security events from multiple sources in a homelab environment. It provides a unified view of honeypot activity, network anomalies, attack chain correlations, and cloud misconfigurations through an interactive terminal dashboard and self-contained HTML reports.

---

## Architecture

```
Log Sources                    Ingestion Layer         Storage        Presentation
─────────────                  ───────────────         ───────        ────────────
Honeypot (JSONL)       ──┐
Network Baseline (JSON) ─┤     ┌─────────────┐     ┌──────────┐   ┌───────────────┐
Attack Correlator (JSON)─┼────>│ Collector    │────>│ SQLite   │──>│ Terminal (Rich)│
Cloud Scanner (JSON)    ─┘     │ + Normalizer │     │ EventDB  │   │ HTML Report    │
                               └─────────────┘     └──────────┘   │ Query Engine   │
HTTP POST /ingest ────────────────────┘                            └───────────────┘
```

### Components

| Package     | Module                | Purpose                                         |
|-------------|----------------------|-------------------------------------------------|
| `ingestion` | `collector.py`       | Directory watcher and HTTP endpoint              |
| `ingestion` | `parsers.py`         | Format-specific log file parsers                 |
| `ingestion` | `normalizer.py`      | Source detection and schema normalization         |
| `storage`   | `database.py`        | SQLite-backed event store with indexed queries   |
| `dashboard` | `terminal_dashboard.py` | Rich-powered live terminal dashboard          |
| `dashboard` | `html_report.py`     | Self-contained HTML report generator             |
| `search`    | `query_engine.py`    | Flexible event search with time-range support    |
| `demo`      | `generator.py`       | Synthetic event generator for all source types   |

## Supported Log Sources

- **Honeypot** — SSH, HTTP, FTP, Telnet, SMB, and RDP connection attempts (JSONL format)
- **Network Baseline** — Port scans, C2 beaconing, data exfiltration, DNS tunneling alerts
- **Attack Correlator** — MITRE ATT&CK kill chain progression with confidence scores
- **Cloud Scanner** — AWS/GCP/Azure misconfiguration findings (S3 public access, open security groups, missing encryption)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Self-Contained Demo

Run the full pipeline with synthetic data — no external infrastructure required:

```bash
python main.py demo
python main.py demo --event-count 100 --no-dashboard
```

### Directory Ingestion

Watch a directory for new log files:

```bash
python main.py ingest --watch-dir ./logs/
python main.py ingest --watch-dir ./logs/ --poll-interval 5
```

### HTTP Ingestion

Start a FastAPI endpoint for real-time event submission:

```bash
python main.py ingest --http --port 8000

# Submit events:
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{"protocol": "SSH", "src_ip": "10.0.0.5", "event_type": "brute_force", "timestamp": "2025-01-01T12:00:00Z"}'
```

### Terminal Dashboard

Launch the interactive Rich dashboard:

```bash
python main.py dashboard
python main.py dashboard --refresh 2
```

### Search

Query stored events with filters:

```bash
python main.py search --severity high --last 24h
python main.py search --source honeypot --keyword brute_force
python main.py search --severity critical --last 7d --limit 100
```

### HTML Report

Generate a self-contained report:

```bash
python main.py report -o sentinel_report.html
```

## Ethical Disclaimer

SENTINEL is designed exclusively for **authorized security monitoring** in controlled homelab and educational environments. It must only be deployed against systems that you own or have explicit written permission to monitor. Unauthorized surveillance or data collection may violate applicable laws and regulations. The authors assume no liability for misuse.
