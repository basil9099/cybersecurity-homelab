# SENTINEL — AI Attack Chain Correlator

SENTINEL ingests outputs from any subset of the homelab's six security tools and uses
traditional ML (DBSCAN, TF-IDF, IsolationForest, NetworkX) to automatically:

- **Correlate** findings across tools into attack **campaigns**
- **Map** each campaign to a **MITRE ATT&CK kill chain phase** (zero-shot TF-IDF cosine similarity)
- **Score** risk per finding and campaign using a weighted composite model
- **Detect** entity-level **attack paths** using NetworkX PageRank + path enumeration
- **Generate** a unified dark-theme **HTML + JSON report**

No LLM or external API calls — fully offline, pure Python ML stack.

## Supported Tool Outputs

| Tool | Parser | Key Entities Extracted |
|------|--------|----------------------|
| SPECTRE (vulnerability scanner) | `spectre_parser.py` | IPs, CVEs, ports |
| NIMBUS (cloud security scanner) | `nimbus_parser.py` | Resources, IPs, domains |
| OSINT Framework | `osint_parser.py` | Domains, IPs, breach data |
| API Security Tester | `api_tester_parser.py` | CVEs, IPs, domains |
| Anomaly Detector | `anomaly_parser.py` | IPs, anomaly scores |
| Network Baseline Monitor | `network_monitor_parser.py` | IPs, ports |

## Installation

```bash
cd projects/sentinel
pip install -r requirements.txt
```

## Usage

### Demo mode (self-contained, no real scan data needed)
```bash
python main.py demo
python main.py demo --output ./my-reports/ --format html
```

### Correlate real tool outputs
```bash
python main.py correlate --inputs spectre.json nimbus.json osint.json
python main.py correlate --input-dir ./scan_results/ --output ./reports/
python main.py correlate --inputs *.json --format json --min-risk 3.0
```

### CLI options
```
python main.py correlate --help

  --inputs FILE [FILE ...]     Tool output files (JSON or CSV)
  --input-dir DIR              Directory to glob for *.json / *.csv
  --output DIR                 Report output directory (default: ./sentinel_reports/)
  --format {html,json,both}    Report format (default: both)
  --dbscan-eps EPS             DBSCAN neighbourhood radius 0–1 (default: 0.4)
  --dbscan-min-samples N       Min findings to form a cluster (default: 2)
  --min-risk SCORE             Minimum campaign risk score to include (default: 0.0)
  --no-isolation-forest        Disable IsolationForest re-ranking
```

## Architecture

```
Input JSONs → Parsers → NormalizedFinding objects
                             │
                    Entity Extraction (regex)
                             │
                    Correlation Graph (NetworkX)
                        ┌────┴────┐
                    DBSCAN     TF-IDF cosine
                  Clustering   → MITRE ATT&CK
                        └────┬────┘
                      Campaign objects
                             │
                    Risk Scoring (weighted)
                    + IsolationForest re-rank
                             │
                    Attack Path Detection
                    (PageRank + paths)
                             │
                    HTML + JSON Reports (Jinja2)
```

## ML Components

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Campaign clustering | DBSCAN (cosine, TF-IDF features) | Group related cross-tool findings |
| Kill chain mapping | TF-IDF + cosine similarity | Zero-shot ATT&CK phase classification |
| Risk re-ranking | IsolationForest | Identify statistically outlier high-risk findings |
| Attack paths | NetworkX PageRank + all_simple_paths | Entity-level attack progression |

## Report Sections

1. **Stat cards** — findings / campaigns / paths / max risk score
2. **Kill chain timeline** — ATT&CK phases with campaign counts
3. **Top attack paths** — entity-level attack progression chains
4. **Campaign table** — sorted by risk score, with phase and entity detail
5. **All findings** — per-finding source, severity, phase, risk score
6. **Tool coverage** — which tools contributed and how many findings each

## Graceful Degradation

- Missing or malformed files: warning logged, pipeline continues with remaining findings
- `n_findings < 2`: error with clear message (minimum for correlation)
- `n_findings < min_samples`: all findings → single campaign (skip DBSCAN)
- `n_findings < 10`: IsolationForest re-ranking skipped
- Graph with `< 3 nodes`: attack path detection skipped
- Any single tool can be omitted — the others still correlate
