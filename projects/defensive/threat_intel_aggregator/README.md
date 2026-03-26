# WATCHTOWER

**Threat Intelligence Feed Aggregator**

WATCHTOWER pulls indicators of compromise (IOCs) from free, publicly available
threat intelligence feeds and cross-references them against local honeypot and
network logs to surface actionable alerts with full TI context.

---

## Supported Feeds

| Feed | Type | Auth | IOC Types | Notes |
|------|------|------|-----------|-------|
| **AbuseIPDB** | REST API | API key (free tier) | IP addresses | Abuse confidence score, category mapping |
| **AlienVault OTX** | REST API | API key (free) | IP, domain, URL, hash | Pulse subscriptions, community intel |
| **URLhaus** | REST API | None | URL, domain, IP | Malicious URL database by abuse.ch |
| **Emerging Threats** | Plain-text list | None | IP addresses | Proofpoint compromised-IP blocklist |

All feeds work fully in **demo mode** without API keys using built-in mock data.

---

## Architecture

```
watchtower/
├── main.py                  # CLI entry point (fetch, correlate, dashboard, demo, check, report)
├── feeds/
│   ├── base_feed.py         # Abstract base class, rate limiter, cache
│   ├── abuseipdb.py         # AbuseIPDB v2 integration
│   ├── alienvault_otx.py    # AlienVault OTX DirectConnect v2
│   ├── urlhaus.py           # abuse.ch URLhaus API
│   ├── emerging_threats.py  # ET compromised-IP blocklist
│   └── feed_manager.py      # Parallel orchestration, deduplication
├── correlation/
│   ├── correlator.py        # Log-to-IOC cross-referencing engine
│   └── ioc_database.py      # SQLite IOC store (upsert, staleness, search)
├── models/
│   ├── indicator.py         # IOC dataclass with auto-type detection
│   └── enrichment.py        # Enrichment result with threat scoring
├── dashboard/
│   ├── terminal_dashboard.py # Rich TUI: stats, threats, correlations, feed health
│   └── html_report.py       # Standalone HTML report generator
├── demo/
│   ├── mock_feeds.py        # Realistic mock feed responses
│   └── sample_logs.py       # Sample logs with deliberate IOC overlap
├── requirements.txt
└── README.md
```

### Data Flow

```
 Threat Feeds ──► FeedManager ──► IOCDatabase (SQLite)
                                        │
 Local Logs ──────► Correlator ─────────┘
                        │
                   EnrichmentResults
                        │
              ┌─────────┴─────────┐
         Terminal Dashboard    HTML Report
```

---

## Quick Start

### 1. Install dependencies

```bash
cd projects/defensive/threat_intel_aggregator
pip install -r requirements.txt
```

### 2. Run the demo (no API keys needed)

```bash
python main.py demo
```

This will:
- Fetch IOCs from mock feeds
- Correlate them against sample honeypot and network logs
- Display a Rich terminal dashboard with statistics, threats, and correlation hits
- Generate an HTML report at `watchtower_demo_report.html`

### 3. Available commands

```bash
python main.py demo                     # Full demo with mock data
python main.py fetch                    # Fetch from real feeds (or demo if no keys)
python main.py fetch --limit 50         # Limit indicators per feed
python main.py correlate                # Correlate logs against IOC database
python main.py correlate --log-file /path/to/honeypot.jsonl
python main.py dashboard                # Terminal dashboard
python main.py check 198.51.100.23      # Look up a single IOC
python main.py report --output report.html  # Generate HTML report
python main.py -v demo                  # Verbose / debug logging
```

---

## API Key Setup

Set environment variables for live feed access:

```bash
export ABUSEIPDB_API_KEY="your-key-here"    # https://www.abuseipdb.com/account/api
export OTX_API_KEY="your-key-here"          # https://otx.alienvault.com/api
```

URLhaus and Emerging Threats do not require API keys.

If no keys are detected, WATCHTOWER automatically falls back to demo mode.

---

## Log Format

The correlator accepts JSONL files (one JSON object per line). It extracts IOCs
from well-known fields:

- **IP fields:** `src_ip`, `dst_ip`, `source_ip`, `dest_ip`, `remote_ip`, `client_ip`, `attacker_ip`
- **Domain fields:** `domain`, `hostname`, `host`, `dns_query`, `server_name`
- **URL fields:** `url`, `request_url`, `uri`
- **Hash fields:** `md5`, `sha1`, `sha256`, `hash`, `file_hash`
- **Free-text extraction:** IPs, domains, URLs, and hashes are also extracted from `message`, `raw`, `payload`, and `data` fields via regex.

---

## Ethical Disclaimer

WATCHTOWER is designed **exclusively for defensive security research** within
authorized homelab environments. The threat intelligence data it consumes is
sourced from publicly available feeds intended for security practitioners.

- Do **not** use this tool or its data for offensive operations.
- Do **not** probe, scan, or attack any IP addresses found in threat feeds.
- Respect the terms of service for each upstream feed provider.
- All mock data uses RFC 5737 documentation IP ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) and fictional domains.

---

## Requirements

- Python 3.10+
- Dependencies: `requests`, `rich`, `pyyaml`, `aiohttp`

## License

This project is part of the cybersecurity-homelab educational repository.
