# OSINT Reconnaissance Framework

An open-source intelligence (OSINT) framework for aggregating publicly available information about targets from multiple sources. Built for penetration testing, threat intelligence, and security research education.

> **Legal notice**: Use only against targets you own or have **explicit written authorization** to test. OSINT queries public data — storage and use of personal data may be regulated by GDPR, CCPA, and other laws.

---

## Features

| Module | Source | API Key Required |
|---|---|---|
| WHOIS / RDAP | IANA, ARIN, RIPE | No |
| DNS Enumeration | Public DNS resolvers | No |
| Zone Transfer | Authoritative nameservers | No |
| Subdomain Brute-force | DNS resolvers | No |
| Certificate Transparency | crt.sh | No |
| Wayback Machine | Internet Archive CDX API | No |
| GitHub Reconnaissance | GitHub REST API | Optional (rate limit) |
| LinkedIn Dorks | Google search operators | No |
| Breach Check | HaveIBeenPwned v3 | **Yes** ($3.50/month) |
| Shodan | Shodan REST API | **Yes** (free tier available) |
| Search Dorks | Google / Bing | Optional |

---

## Installation

```bash
# Clone or navigate to the project
cd projects/osint_framework

# Install dependencies
pip install -r requirements.txt

# Verify
python osint_framework.py --help
```

---

## Windows Executable (Standalone)

A pre-built Windows `.exe` is available on the [GitHub Releases](../../releases) page — no Python installation required.

### Download & run

```powershell
# Download the latest release, then:
osint_framework.exe -t example.com --all

# Launch the web GUI
osint_framework.exe --gui
```

### Build from source

```bash
pip install -r requirements.txt pyinstaller
python build_windows.py          # output: dist/osint_framework.exe
python build_windows.py --clean  # clean build artifacts first
```

> **Antivirus note:** PyInstaller executables are occasionally flagged as false positives by antivirus software. Verify the file against the SHA256 hash published in the GitHub Release notes.

---

## Quick Start

### Free sources only (no API keys needed)

```bash
# WHOIS + DNS + crt.sh + Wayback Machine + search dorks
python osint_framework.py -t example.com --whois --dns --crtsh --wayback --dorks
```

### Full recon with all modules

```bash
python osint_framework.py -t example.com --all \
  --github-org exampleorg \
  --github-token ghp_YOUR_TOKEN \
  --hibp-key YOUR_HIBP_KEY \
  --shodan-key YOUR_SHODAN_KEY \
  --emails admin@example.com ceo@example.com \
  --output-dir ./reports
```

### Breach check only

```bash
python osint_framework.py -t example.com --breach \
  --emails user@example.com \
  --hibp-key YOUR_KEY
```

### DNS enumeration with custom wordlist

```bash
python osint_framework.py -t example.com --dns \
  --subdomain-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --dns-threads 50
```

### Web GUI

```bash
# Launch the browser-based GUI on port 8080 (default)
python osint_framework.py --gui

# Use a custom port
python osint_framework.py --gui --gui-port 9090
```

Open `http://localhost:8080` in your browser to configure targets, select modules, enter API keys, and run scans with real-time progress streaming.

---

## Output

Reports are generated in `./osint_reports/` (configurable with `--output-dir`):

| Format | Description |
|---|---|
| `.json` | Machine-readable full profile — import into other tools |
| `.txt`  | Human-readable text report for quick review |
| `.html` | Self-contained interactive report with risk matrix and relationship table |

---

## Module Details

### WHOIS / RDAP (`modules/whois_recon.py`)

Queries WHOIS databases for:
- Registrant name, organisation, email, phone, address
- Registrar and nameservers
- Domain creation / expiration dates
- Hosting provider hints (Cloudflare, AWS Route 53, etc.)

Uses `python-whois` with RDAP JSON API fallback.

### DNS Reconnaissance (`modules/dns_recon.py`)

- All record types: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV
- **Zone transfer attempt (AXFR)** — reveals full DNS zone on misconfigured servers
- **Subdomain brute-force** — built-in wordlist + custom wordlist support (multi-threaded)
- SPF, DMARC, DKIM policy extraction
- MX server mapping

### Social Media Recon (`modules/social_recon.py`)

- **GitHub**: organisation metadata, public member enumeration, repository listing, code search for secrets
- **LinkedIn**: Google dork generation for employee discovery (no scraping — respects ToS)
- **Email pattern inference**: given known addresses, predicts others (`first.last@domain`)
- **Email generation**: generates candidate addresses for discovered employee names

### Breach Database (`modules/breach_check.py`)

- **HaveIBeenPwned v3**: breach and paste lookup for email addresses
- **Pwned Passwords**: k-anonymity password hash check (safe for live engagements — server never receives full hash)
- **DeHashed**: multi-field breach search (email, username, IP, name)
- Risk summarisation with CRITICAL/HIGH/MEDIUM/LOW classification

### Search Engine Recon (`modules/search_recon.py`)

- **Shodan**: host info (ports, banners, CVEs, geolocation), custom search queries
- **crt.sh**: certificate transparency subdomain enumeration (free, no key)
- **Wayback Machine**: availability check, snapshot history, full URL archive crawl
- **Google Custom Search**: programmatic dork execution
- **Bing Search**: alternative search engine
- **Dork generation**: 40+ pre-built dorks across 7 categories (sensitive files, admin panels, exposed services, emails, error pages, cached data)

### Reporter (`modules/reporter.py`)

- Builds unified target profile from all module outputs
- Risk assessment matrix with finding severity classification
- Relationship mapping (entity graph edges for mind-map tools)
- JSON, plain-text, and HTML report generation

---

## Architecture

```
osint_framework.py          ← CLI entry point / orchestrator
modules/
  __init__.py
  whois_recon.py            ← WHOIS and RDAP queries
  dns_recon.py              ← DNS enumeration and zone transfers
  social_recon.py           ← GitHub, LinkedIn, email patterns
  breach_check.py           ← HIBP, DeHashed breach queries
  search_recon.py           ← Shodan, crt.sh, Wayback Machine, dorks
  reporter.py               ← Profile aggregation and report generation
gui/
  __init__.py
  app.py                    ← FastAPI web GUI backend (SSE, scan API)
  templates/
    index.html              ← Self-contained SPA frontend
osint_framework.spec        ← PyInstaller build specification
build_windows.py            ← Local build helper for Windows exe
osint_reports/              ← Generated reports (created at runtime)
```

---

## API Keys

| Service | How to obtain | Cost |
|---|---|---|
| HaveIBeenPwned | https://haveibeenpwned.com/API/v3 | $3.50/month |
| Shodan | https://account.shodan.io/ | Free tier available |
| GitHub | https://github.com/settings/tokens | Free |
| Google CSE | https://programmablesearchengine.google.com/ | Free (100 queries/day) |
| Bing Search | https://portal.azure.com/ | Free tier available |
| DeHashed | https://www.dehashed.com/profile | Paid |

Store keys in environment variables rather than passing on the command line:

```bash
export HIBP_KEY="your_key"
export SHODAN_KEY="your_key"
export GITHUB_TOKEN="ghp_..."

python osint_framework.py -t example.com --all \
  --hibp-key "$HIBP_KEY" \
  --shodan-key "$SHODAN_KEY" \
  --github-token "$GITHUB_TOKEN"
```

---

## Comparison with Commercial Tools

| Feature | This Framework | Maltego | SpiderFoot | theHarvester |
|---|---|---|---|---|
| WHOIS | ✓ | ✓ | ✓ | ✓ |
| DNS enum | ✓ | ✓ | ✓ | ✓ |
| Subdomain brute | ✓ | ✓ (paid) | ✓ | ✓ |
| GitHub recon | ✓ | ✓ (paid) | ✓ | ✗ |
| Breach check | ✓ | ✓ (paid) | ✓ | ✗ |
| Shodan | ✓ | ✓ (paid) | ✓ | ✗ |
| HTML reports | ✓ | ✓ | ✓ | ✗ |
| JSON export | ✓ | ✓ | ✓ | ✗ |
| Source available | ✓ | ✗ | ✓ | ✓ |
| Cost | Free | $$$  | Free/paid | Free |

---

## Limitations

- **Rate limits**: APIs impose request limits. The framework adds delays where necessary.
- **Information availability**: WHOIS privacy services (WhoisGuard, Domains By Proxy) redact registrant details.
- **LinkedIn**: Direct scraping requires login and violates ToS. This framework uses Google dorks instead.
- **HIBP accuracy**: Only covers breaches that have been reported to HIBP. Unknown/unreported breaches will not appear.
- **Shodan free tier**: Limited to 1 result per search and no historical data.
- **Legal**: This tool is for authorized testing only. Unauthorised reconnaissance may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), GDPR, and other laws.

---

## Key Concepts Learned

- **OSINT workflow**: target → employees → infrastructure → applications → data
- **Passive vs active recon**: WHOIS/DNS/crt.sh query third parties (passive); zone transfers and subdomain brute-force query the target's servers (semi-active)
- **Zone transfer (AXFR)**: DNS misconfiguration that leaks entire zone — should always be disabled
- **SPF/DMARC**: email authentication mechanisms; absence enables spoofing
- **k-anonymity**: privacy-preserving password hash checking technique used by HIBP
- **Certificate transparency**: public log of all issued TLS certs — excellent passive subdomain source
- **Credential stuffing**: using leaked passwords from breaches to attack other services
- **Entity correlation**: linking the same person across multiple platforms (same username, email, photo)
