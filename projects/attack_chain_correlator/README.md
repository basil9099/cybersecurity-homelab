# Attack Chain Correlator

AI-powered MITRE ATT&CK kill chain correlator with Bayesian scoring for the cybersecurity homelab.

## Overview

Correlates alerts from multiple security tools (Network Baseline Monitor, Splunk SIEM, NIMBUS Cloud Scanner, SPECTRE Vulnerability Scanner) into unified attack chain timelines. Uses a kill chain state machine and Bayesian probability scoring to distinguish real multi-stage attacks from coincidental noise.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Ingestion Layer                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Network  │  │  Splunk  │  │  Cloud   │  │   Vuln   │    │
│  │ Baseline │  │   SIEM   │  │ Scanner  │  │ Scanner  │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       └──────────────┴──────────────┴──────────────┘         │
│                         │                                     │
│              ┌──────────▼──────────┐                         │
│              │  Normalized Alert   │                         │
│              │      Schema         │                         │
│              └──────────┬──────────┘                         │
├──────────────────────────┼───────────────────────────────────┤
│                Correlation Engine  │                          │
│              ┌──────────▼──────────┐                         │
│              │   ATT&CK Mapping    │                         │
│              └──────────┬──────────┘                         │
│              ┌──────────▼──────────┐                         │
│              │  Kill Chain State   │                         │
│              │     Machine         │                         │
│              └──────────┬──────────┘                         │
│              ┌──────────▼──────────┐                         │
│              │  Bayesian Scoring   │                         │
│              └──────────┬──────────┘                         │
│              ┌──────────▼──────────┐                         │
│              │  Chain Manager      │                         │
│              └──────────┬──────────┘                         │
├──────────────────────────┼───────────────────────────────────┤
│                    Output Layer    │                          │
│    ┌─────────┐  ┌────────▼────┐  ┌──────────┐              │
│    │ SQLite  │  │  FastAPI +  │  │   SSE    │              │
│    │   DB    │  │  REST API   │  │ Streaming│              │
│    └─────────┘  └─────────────┘  └──────────┘              │
└──────────────────────────────────────────────────────────────┘
```

## Components

### Ingestion Layer (`ingestion/`)
- **schema.py** — Unified `NormalizedAlert` dataclass consumed by the correlation engine
- **network.py** — Reads from Network Baseline Monitor's SQLite alerts_log
- **siem.py** — Parses Splunk CSV/JSON exports
- **cloud.py** — Ingests NIMBUS cloud scanner findings

### MITRE ATT&CK Mappings (`mappings/`)
- **mitre_attack.py** — Maps 25+ alert types to ATT&CK techniques and tactics with kill chain ordering

### Correlation Engine (`correlation/`)
- **attack_graph.py** — Per-entity kill chain state machine tracking tactic progression
- **scoring.py** — Bayesian posterior calculation + weighted composite scoring (completeness, velocity, ordering, quality, diversity)
- **chains.py** — Chain lifecycle management (creation, escalation, resolution)

### Storage (`storage/`)
- **database.py** — SQLite persistence for alerts, chains, and score history

### API (`api/`)
- **server.py** — FastAPI server with REST endpoints and SSE real-time streaming

### Demo (`demo/`)
- **scenarios.py** — 5 synthetic attack scenarios for testing (APT intrusion, insider threat, cloud breach, red team, false positives)

## Quick Start

### Run the demo scenarios
```bash
cd projects/attack_chain_correlator
python -m demo.scenarios
```

### Start the API server
```bash
pip install -r requirements.txt
uvicorn api.server:app --reload --port 8080
```

### Push an alert via API
```bash
curl -X POST http://localhost:8080/api/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "source": "network_baseline",
    "anomaly_type": "port_scan",
    "severity": "medium",
    "score": 6.5,
    "src_entity": "10.0.0.50",
    "tactic": "discovery"
  }'
```

### Stream real-time updates
```bash
curl -N http://localhost:8080/api/stream
```

## Scoring Model

The Bayesian scorer combines five weighted signals:

| Signal | Weight | Description |
|--------|--------|-------------|
| Completeness | 30% | Kill chain stage coverage (more stages = higher) |
| Velocity | 20% | Temporal compression (faster progression = higher) |
| Order | 20% | Kill chain sequence correctness |
| Quality | 15% | Average alert severity/confidence |
| Diversity | 15% | Multi-source/technique correlation |

Escalation levels:
- **None** (score < 2.5) — Insufficient evidence
- **Watch** (2.5–4.5) — Early-stage activity, monitor
- **Alert** (4.5–7.0) — Probable attack chain, investigate
- **Critical** (7.0+) — High-confidence multi-stage attack, respond immediately
