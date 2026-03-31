"""Keyword extraction and source credibility scoring."""

from __future__ import annotations

import re

_SECURITY_TERMS = {
    "cve", "zero-day", "0day", "rce", "remote code execution",
    "sql injection", "sqli", "xss", "cross-site scripting",
    "exploit", "vulnerability", "malware", "ransomware", "trojan",
    "backdoor", "apt", "phishing", "spearphishing", "breach",
    "data leak", "credential stuffing", "brute force", "botnet",
    "command injection", "privilege escalation", "buffer overflow",
    "deserialization", "ssrf", "idor", "path traversal",
    "denial of service", "ddos", "supply chain", "lateral movement",
    "persistence", "exfiltration", "c2", "command and control",
    "threat actor", "campaign", "indicator of compromise", "ioc",
    "mitre att&ck", "ttps", "kill chain", "cisa", "kev",
    "patch", "update", "advisory", "critical", "actively exploited",
}

_CREDIBLE_SOURCES = {
    "krebs on security": 0.95,
    "the hacker news": 0.85,
    "bleepingcomputer": 0.90,
    "talos intelligence": 0.92,
    "dark reading": 0.80,
    "securityweek": 0.82,
    "schneier on security": 0.93,
    "sans isc": 0.90,
    "recorded future": 0.88,
    "mandiant": 0.93,
    "crowdstrike": 0.91,
    "unit 42": 0.90,
    "@swiftonsecurity": 0.90,
    "@malwaretech": 0.92,
    "@briankrebs": 0.95,
    "@taviso": 0.93,
    "@gossithdog": 0.88,
}


def extract_keywords(text: str) -> list[str]:
    """Extract security-relevant keywords from text."""
    text_lower = text.lower()
    found = []
    for term in _SECURITY_TERMS:
        if term in text_lower:
            found.append(term)

    # Also extract CVE references
    cves = re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    found.extend(c.upper() for c in cves)

    return list(set(found))


def compute_credibility(author: str, source: str) -> float:
    """Score source credibility based on known sources."""
    check = (author or "").lower()
    for name, score in _CREDIBLE_SOURCES.items():
        if name in check:
            return score

    check = (source or "").lower()
    for name, score in _CREDIBLE_SOURCES.items():
        if name in check:
            return score

    # Unknown source
    return 0.5


def classify_sentiment(text: str) -> str:
    """Classify post sentiment as alert, analysis, or neutral."""
    text_lower = text.lower()
    alert_phrases = [
        "actively exploited", "zero-day", "0day", "critical vulnerability",
        "emergency patch", "urgent", "breach", "under attack", "in the wild",
    ]
    if any(p in text_lower for p in alert_phrases):
        return "alert"

    analysis_phrases = [
        "analysis", "deep dive", "research", "investigation", "report",
        "breakdown", "technical details", "reverse engineer",
    ]
    if any(p in text_lower for p in analysis_phrases):
        return "analysis"

    return "neutral"
