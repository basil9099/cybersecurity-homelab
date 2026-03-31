# MONITOR THE SITUATION

Cybersecurity situational awareness dashboard that aggregates real-time threat intelligence from multiple sources into a single SOC-style operational display.

```
 __  __  ___  _   _ ___ _____ ___  ____
|  \/  |/ _ \| \ | |_ _|_   _/ _ \|  _ \
| |\/| | | | |  \| || |  | || | | | |_) |
| |  | | |_| | |\  || |  | || |_| |  _ <
|_|  |_|\___/|_| \_|___| |_| \___/|_| \_\
  THE SITUATION
```

## Features

| Module | Description | Data Sources |
|--------|-------------|--------------|
| **Global Threat Map** | Interactive world map showing attack origins with geolocation | GreyNoise, AbuseIPDB, AlienVault OTX, MaxMind GeoIP2 |
| **CVE Velocity Tracker** | Real-time CVE monitoring with CVSS scoring and EPSS prediction | NVD API v2, FIRST EPSS |
| **Threat Actor Leaderboard** | APT groups ranked by campaign frequency and technique sophistication | MITRE ATT&CK STIX |
| **Exploit Availability Monitor** | Tracks CVE-to-exploit lifecycle with time-to-weaponization metrics | GitHub, Exploit-DB, Metasploit, Nuclei |
| **Social Intel Feed** | Security researcher posts and blog aggregation with credibility scoring | RSS feeds, Mastodon (infosec.exchange) |
| **Infrastructure Health** | Real-time collector status monitoring | Internal |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  React Frontend (Vite + react-simple-maps)                       │
│  ┌──────────┬──────────────────────────┬───────────┐            │
│  │ Actors   │     Global Threat Map    │ Exploits  │            │
│  │ Leader   │      (centerpiece)       │ Timeline  │            │
│  │ board    │                          │ + Alerts  │            │
│  ├──────────┴──────────────────────────┴───────────┤            │
│  │          Social Intel Ticker (scrolling)         │            │
│  └──────────────────────────────────────────────────┘            │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST + WebSocket
┌──────────────────────────┴──────────────────────────────────────┐
│  FastAPI Backend                                                 │
│  ┌────────────┐  ┌──────────┐  ┌────────────┐  ┌────────────┐  │
│  │ Collectors │→ │ Services │→ │ API Layer  │→ │ WebSocket  │  │
│  │ (9 source  │  │ (ranking,│  │ (REST      │  │ Hub        │  │
│  │  adapters) │  │  velocity│  │  endpoints)│  │ (real-time)│  │
│  └────────────┘  └──────────┘  └────────────┘  └────────────┘  │
│       ↑                                                          │
│  ┌────────────┐  ┌──────────────────────────────────────────┐   │
│  │ APScheduler│  │              SQLite Database              │   │
│  │ (async     │  │  threat_events | cves | threat_actors     │   │
│  │  intervals)│  │  exploits | social_posts | alerts         │   │
│  └────────────┘  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Demo Mode (no API keys needed)

```bash
# Backend
cd projects/defensive/monitor_the_situation
pip install -r requirements.txt
python main.py demo

# Frontend (in a separate terminal)
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 to view the dashboard.

### Live Mode (with API keys)

Set environment variables:
```bash
export MTS_NVD_API_KEY="your-key"
export MTS_GREYNOISE_API_KEY="your-key"
export MTS_ABUSEIPDB_API_KEY="your-key"
export MTS_OTX_API_KEY="your-key"
export MTS_GITHUB_TOKEN="your-token"
```

```bash
python main.py serve
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `python main.py demo` | Launch with mock data (no API keys needed) |
| `python main.py serve` | Start the API server |
| `python main.py serve --demo` | Start server in demo mode |
| `python main.py fetch` | One-shot fetch from all sources |
| `python main.py reset-db` | Reset the database |

## API Endpoints

### REST

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threat-map` | Threat events with filters |
| GET | `/api/threat-map/countries` | Country aggregations |
| GET | `/api/threat-map/stats` | Summary statistics |
| GET | `/api/cves` | Paginated CVE list |
| GET | `/api/cves/velocity` | Publication velocity data |
| GET | `/api/cves/critical` | CVSS 9.0+ CVEs |
| GET | `/api/cves/{id}` | CVE detail with linked exploits |
| GET | `/api/actors` | Ranked threat actor leaderboard |
| GET | `/api/actors/{id}` | Actor detail with TTPs |
| GET | `/api/exploits` | Exploit list with filters |
| GET | `/api/exploits/lifecycle` | Time-to-exploit metrics |
| GET | `/api/exploits/alerts` | Weaponization alerts |
| GET | `/api/social/feed` | Social intel feed |
| GET | `/api/social/trending` | Trending keywords |
| GET | `/api/health` | System health |
| GET | `/api/alerts` | Active alerts |

### WebSocket

Connect to `/ws` for real-time updates:
```json
{"subscribe": ["threat_map", "cves", "exploits", "social", "alerts"]}
```

## Data Collection Schedule

| Collector | Live Interval | Demo Interval |
|-----------|--------------|---------------|
| NVD (CVEs + EPSS) | 15 min | 30 sec |
| GreyNoise | 1 hour | 10 sec |
| AbuseIPDB | 1 hour | 10 sec |
| AlienVault OTX | 1 hour | 15 sec |
| GitHub PoCs | 30 min | 20 sec |
| Exploit-DB | 30 min | 20 sec |
| RSS Feeds | 5 min | 10 sec |
| Mastodon | 5 min | 10 sec |
| MITRE ATT&CK | 24 hours | Startup only |

## Tech Stack

**Backend:** Python, FastAPI, APScheduler, aiohttp, SQLite, Pydantic

**Frontend:** React 18, Vite, react-simple-maps, d3-scale

## Project Structure

```
monitor_the_situation/
├── main.py                    # CLI entry point
├── requirements.txt
├── backend/
│   ├── app.py                 # FastAPI app factory
│   ├── config.py              # Environment-based settings
│   ├── database.py            # SQLite schema + helpers
│   ├── scheduler.py           # APScheduler job registration
│   ├── models/                # Pydantic data models
│   ├── collectors/            # 9 data source adapters
│   ├── services/              # Business logic (ranking, velocity, alerting)
│   ├── api/                   # REST routers + WebSocket hub
│   └── demo/                  # Mock data generators
└── frontend/
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx
        ├── hooks/             # useWebSocket, useApi, useFullscreen
        ├── context/           # Dashboard state
        └── components/
            ├── layout/        # DashboardShell, PanelFrame, StatusBar
            ├── map/           # ThreatMap, MapTooltip, MapLegend
            ├── cve/           # CVEVelocityChart, CriticalAlerts
            ├── actors/        # ActorLeaderboard, TTPMatrix
            ├── exploits/      # ExploitTimeline, WeaponizationAlerts
            ├── social/        # SocialTicker, SocialFeed
            ├── health/        # CollectorStatus
            └── shared/        # MiniChart, SeverityBadge, TimeAgo, AlertBanner
```
