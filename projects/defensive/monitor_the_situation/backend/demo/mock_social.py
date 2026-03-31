"""Mock social media posts from security researchers and blogs."""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from backend.demo.mock_cves import get_mock_cve_ids

_RSS_SOURCES = [
    ("Krebs on Security", 0.95),
    ("The Hacker News", 0.85),
    ("BleepingComputer", 0.90),
    ("Talos Intelligence", 0.92),
    ("Dark Reading", 0.80),
    ("SecurityWeek", 0.82),
    ("Ars Technica Security", 0.85),
    ("Schneier on Security", 0.93),
    ("SANS ISC", 0.90),
    ("Recorded Future", 0.88),
]

_MASTODON_AUTHORS = [
    ("@SwiftOnSecurity@infosec.exchange", 0.90),
    ("@malwaretech@infosec.exchange", 0.92),
    ("@briankrebs@infosec.exchange", 0.95),
    ("@taviso@infosec.exchange", 0.93),
    ("@GossiTheDog@infosec.exchange", 0.88),
    ("@campuscodi@infosec.exchange", 0.85),
    ("@caborunderro@infosec.exchange", 0.75),
    ("@threatresearch@infosec.exchange", 0.80),
    ("@ncscuk@infosec.exchange", 0.90),
    ("@random_researcher@infosec.exchange", 0.45),
]

_TEMPLATES = [
    {
        "title": "Critical {product} vulnerability under active exploitation",
        "content": "BREAKING: A critical vulnerability in {product} ({cve}) is being actively exploited in the wild. CVSS score of {score}. Patch immediately. Seeing mass scanning from multiple threat actors. #infosec #vulnerability",
        "sentiment": "alert",
        "keywords": ["active-exploitation", "critical", "patch"],
    },
    {
        "title": "New zero-day discovered in {product}",
        "content": "Researchers have disclosed a zero-day vulnerability in {product} that allows remote code execution. No patch available yet. {cve} assigned. Workaround: disable {component}. #zeroday #cybersecurity",
        "sentiment": "alert",
        "keywords": ["zero-day", "rce", "no-patch"],
    },
    {
        "title": "APT group targets {sector} organizations with new malware",
        "content": "A sophisticated threat actor is targeting {sector} organizations using a previously unknown backdoor. The campaign leverages spearphishing and exploits {cve}. IOCs available in our report. #apt #threatintel",
        "sentiment": "alert",
        "keywords": ["apt", "malware", "campaign"],
    },
    {
        "title": "Analysis: {product} vulnerability {cve} exploitation timeline",
        "content": "Deep dive into the exploitation timeline of {cve} affecting {product}. From disclosure to weaponization took only {days} days. PoC code appeared on GitHub within hours. Here's what defenders need to know. #threatintel",
        "sentiment": "analysis",
        "keywords": ["analysis", "exploitation-timeline", "poc"],
    },
    {
        "title": "Ransomware group claims attack on {sector} company",
        "content": "The {group} ransomware group has claimed responsibility for attacking a major {sector} company, allegedly exfiltrating 500GB of data. Negotiations ongoing. #ransomware #databreach",
        "sentiment": "alert",
        "keywords": ["ransomware", "data-breach", "extortion"],
    },
    {
        "title": "Patch Tuesday: {count} vulnerabilities fixed including {critical} critical",
        "content": "Microsoft's latest Patch Tuesday addresses {count} vulnerabilities, {critical} rated critical. Notable fixes include {cve} ({product}). Prioritize patching for internet-facing systems. #patching",
        "sentiment": "neutral",
        "keywords": ["patch-tuesday", "microsoft", "patching"],
    },
    {
        "title": "CISA adds {cve} to Known Exploited Vulnerabilities catalog",
        "content": "CISA has added {cve} to the KEV catalog, requiring federal agencies to patch by {deadline}. The vulnerability in {product} is being exploited by multiple threat groups. #cisa #kev",
        "sentiment": "alert",
        "keywords": ["cisa", "kev", "mandatory-patch"],
    },
    {
        "title": "New technique bypasses EDR detection on Windows",
        "content": "Security researchers have published a new technique that bypasses several popular EDR solutions on Windows. The method uses {technique} to evade kernel-level monitoring. Details at our blog. #edr #evasion",
        "sentiment": "analysis",
        "keywords": ["edr-bypass", "windows", "evasion-technique"],
    },
    {
        "title": "Threat intelligence report: {group} shifts tactics",
        "content": "Our latest threat report shows {group} has shifted from spearphishing to exploiting edge devices. New TTPs include use of living-off-the-land binaries and custom implants. Full MITRE mapping available. #threatintel",
        "sentiment": "analysis",
        "keywords": ["threat-report", "ttp-change", "edge-devices"],
    },
    {
        "title": "Open source tool released for detecting {product} compromise",
        "content": "We've released an open-source scanner to detect indicators of compromise related to {cve} in {product}. Check your environments ASAP, especially if you delayed patching. GitHub link in thread. #dfir",
        "sentiment": "neutral",
        "keywords": ["detection-tool", "ioc-scanner", "open-source"],
    },
]

_PRODUCTS = ["Fortinet FortiOS", "Ivanti Connect Secure", "Cisco IOS XE",
             "VMware vCenter", "Apache Struts", "Citrix NetScaler",
             "Palo Alto PAN-OS", "GitLab CE/EE", "Confluence Server"]
_SECTORS = ["healthcare", "financial services", "government", "energy", "education", "manufacturing"]
_GROUPS = ["LockBit", "BlackCat", "Royal", "Cl0p", "Play", "BianLian"]
_TECHNIQUES = ["direct syscalls", "callback-based shellcode", "NTFS transactions", "hardware breakpoints"]
_COMPONENTS = ["remote access module", "admin interface", "SSL VPN", "management API"]


def generate_mock_social(count: int = 30) -> list[dict]:
    now = datetime.now(timezone.utc)
    random.seed(45)
    cve_ids = get_mock_cve_ids()
    records = []

    for i in range(count):
        tmpl = random.choice(_TEMPLATES)
        is_rss = random.random() > 0.4
        cve = random.choice(cve_ids[:15])  # reference recent CVEs

        replacements = {
            "product": random.choice(_PRODUCTS),
            "cve": cve,
            "score": f"{random.uniform(7.0, 10.0):.1f}",
            "sector": random.choice(_SECTORS),
            "group": random.choice(_GROUPS),
            "days": str(random.randint(1, 14)),
            "count": str(random.randint(50, 130)),
            "critical": str(random.randint(3, 12)),
            "deadline": (now + timedelta(days=random.randint(7, 21))).strftime("%Y-%m-%d"),
            "technique": random.choice(_TECHNIQUES),
            "component": random.choice(_COMPONENTS),
        }

        title = tmpl["title"].format(**replacements)
        content = tmpl["content"].format(**replacements)

        if is_rss:
            source_name, credibility = random.choice(_RSS_SOURCES)
            source_type = "rss"
            author = source_name
        else:
            author, credibility = random.choice(_MASTODON_AUTHORS)
            source_type = "mastodon"

        hours_ago = random.uniform(0, 6)
        pub_date = now - timedelta(hours=hours_ago)
        pid = hashlib.sha256(f"social:{i}:{source_type}".encode()).hexdigest()[:16]

        keywords = tmpl["keywords"] + [cve.lower()]

        records.append({
            "id": pid,
            "source": source_type,
            "author": author,
            "title": title,
            "content": content,
            "url": f"https://example.com/post/{pid}",
            "published_date": pub_date.isoformat(),
            "keywords": keywords,
            "credibility": credibility,
            "sentiment": tmpl["sentiment"],
            "related_cves": [cve],
            "fetched_at": now.isoformat(),
        })

    return records
