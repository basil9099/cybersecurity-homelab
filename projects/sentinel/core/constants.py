"""
SENTINEL constants — MITRE ATT&CK phases, severity/tool weights.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Severity base scores (0–10)
# ---------------------------------------------------------------------------
SEVERITY_BASE: dict[str, float] = {
    "critical": 10.0,
    "high":      8.0,
    "medium":    5.0,
    "low":       2.0,
    "info":      0.5,
}

# ---------------------------------------------------------------------------
# Source tool reliability weights (higher = more actionable / fewer FPs)
# ---------------------------------------------------------------------------
TOOL_WEIGHTS: dict[str, float] = {
    "spectre":         1.00,   # Port scan + CVE correlation — high signal
    "nimbus":          0.90,   # Cloud misconfiguration — high signal
    "api_tester":      0.95,   # Active exploit confirmation — very high signal
    "anomaly":         0.70,   # ML anomaly — moderate FP risk
    "network_monitor": 0.75,   # Behavioural — moderate FP risk
    "osint":           0.60,   # Passive intelligence — low impact alone
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK kill chain phases + representative keyword phrases
# Used by KillChainMapper as zero-shot TF-IDF corpus
# ---------------------------------------------------------------------------
MITRE_PHASES: dict[str, list[str]] = {
    "Reconnaissance": [
        "port scan", "port scanning", "DNS enumeration", "WHOIS lookup",
        "subdomain discovery", "certificate transparency", "shodan query",
        "breach data lookup", "email harvest", "asset discovery",
        "network enumeration", "service fingerprint", "banner grab",
        "open port detection", "host discovery",
    ],
    "Resource Development": [
        "credential acquisition", "infrastructure setup", "exploit kit",
        "tool acquisition", "c2 infrastructure", "staging server",
    ],
    "Initial Access": [
        "SQL injection", "authentication bypass", "auth bypass",
        "phishing", "exposed service", "public bucket", "open port",
        "default credential", "login bypass", "unauthenticated access",
        "remote exploit", "web shell upload", "file inclusion",
    ],
    "Execution": [
        "command injection", "script execution", "remote code execution",
        "RCE", "OS command", "shell command", "arbitrary code",
        "code execution", "log4shell", "log4j",
    ],
    "Persistence": [
        "backdoor", "scheduled task", "registry modification",
        "startup item", "cronjob", "service installation", "webshell",
    ],
    "Privilege Escalation": [
        "IDOR", "authorization flaw", "privilege escalation",
        "misconfiguration", "role escalation", "access control bypass",
        "vertical privilege", "horizontal privilege", "broken access control",
    ],
    "Defense Evasion": [
        "obfuscation", "log deletion", "anomaly score", "baseline deviation",
        "signature bypass", "anti-forensics", "log tampering",
        "unusual pattern", "deviation from baseline",
    ],
    "Credential Access": [
        "credential", "password", "hash", "breach exposure",
        "haveibeenpwned", "leaked credentials", "password spray",
        "brute force", "credential stuffing", "plaintext password",
    ],
    "Discovery": [
        "network scan", "service enumeration", "host discovery",
        "internal scan", "lateral movement detection", "asset inventory",
        "directory traversal", "path traversal",
    ],
    "Lateral Movement": [
        "lateral movement", "internal pair", "east-west traffic",
        "pivoting", "internal host", "move through network",
        "internal connection", "peer-to-peer",
    ],
    "Collection": [
        "data collection", "sensitive data", "exfiltration preparation",
        "staging data", "file enumeration", "database dump",
    ],
    "Command and Control": [
        "beaconing", "C2", "command and control", "periodic connection",
        "external callback", "reverse shell", "covert channel",
        "tunnelling", "DNS tunneling",
    ],
    "Exfiltration": [
        "external bytes out", "data exfiltration", "large upload",
        "outbound spike", "high outbound bytes", "data transfer out",
        "exfil", "exfiltration", "large outbound",
    ],
    "Impact": [
        "denial of service", "ICMP flood", "volume surge", "ransomware",
        "data destruction", "service disruption", "DoS attack",
        "SYN flood", "bandwidth exhaustion",
    ],
}

# Phase risk multipliers — later kill-chain phases = higher urgency
PHASE_MULTIPLIERS: dict[str, float] = {
    "Reconnaissance":       0.40,
    "Resource Development": 0.45,
    "Initial Access":       0.70,
    "Execution":            0.85,
    "Persistence":          0.80,
    "Privilege Escalation": 0.90,
    "Defense Evasion":      0.75,
    "Credential Access":    0.80,
    "Discovery":            0.60,
    "Lateral Movement":     0.95,
    "Collection":           0.85,
    "Command and Control":  0.90,
    "Exfiltration":         1.00,
    "Impact":               1.00,
    "Unknown":              0.50,
}

# Ordered phase list for kill-chain timeline rendering
PHASE_ORDER: list[str] = list(MITRE_PHASES.keys())
