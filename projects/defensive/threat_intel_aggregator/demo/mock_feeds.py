"""Mock feed responses for demo mode -- realistic fake IOC data.

The IP addresses used here are drawn from documentation / TEST-NET ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and a handful of
commonly-seen-in-exercises addresses to keep things realistic while
avoiding collisions with real infrastructure.
"""

from __future__ import annotations

# ======================================================================
# Shared "known-bad" values that also appear in sample_logs.py so the
# correlator produces hits during demo runs.
# ======================================================================
KNOWN_BAD_IPS = [
    "198.51.100.23",
    "203.0.113.42",
    "198.51.100.77",
    "203.0.113.99",
    "192.0.2.15",
]

KNOWN_BAD_DOMAINS = [
    "malware-c2.evil.xyz",
    "phish-login.badactor.top",
    "dropper.darknet.ru",
]

KNOWN_BAD_URLS = [
    "http://198.51.100.23:8080/bins/mirai.arm7",
    "http://malware-c2.evil.xyz/gate.php",
    "https://phish-login.badactor.top/wp-login.php",
]

KNOWN_BAD_HASHES = [
    "e99a18c428cb38d5f260853678922e03",  # MD5
    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",  # SHA-1
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",  # SHA-256
]

# ======================================================================
# AbuseIPDB mock data
# ======================================================================
MOCK_ABUSEIPDB_BLACKLIST: list[dict] = [
    {
        "ipAddress": "198.51.100.23",
        "abuseConfidenceScore": 95,
        "categories": [18, 22, 15],
        "countryCode": "RU",
        "totalReports": 487,
    },
    {
        "ipAddress": "203.0.113.42",
        "abuseConfidenceScore": 88,
        "categories": [14, 15, 21],
        "countryCode": "CN",
        "totalReports": 312,
    },
    {
        "ipAddress": "198.51.100.77",
        "abuseConfidenceScore": 82,
        "categories": [4, 15],
        "countryCode": "BR",
        "totalReports": 198,
    },
    {
        "ipAddress": "203.0.113.99",
        "abuseConfidenceScore": 76,
        "categories": [8, 21],
        "countryCode": "NG",
        "totalReports": 145,
    },
    {
        "ipAddress": "192.0.2.15",
        "abuseConfidenceScore": 70,
        "categories": [10, 19],
        "countryCode": "UA",
        "totalReports": 89,
    },
    {
        "ipAddress": "198.51.100.200",
        "abuseConfidenceScore": 65,
        "categories": [22],
        "countryCode": "KR",
        "totalReports": 55,
    },
    {
        "ipAddress": "203.0.113.150",
        "abuseConfidenceScore": 60,
        "categories": [14, 15],
        "countryCode": "VN",
        "totalReports": 33,
    },
]

MOCK_ABUSEIPDB_CHECKS: dict[str, dict] = {
    "198.51.100.23": {
        "ipAddress": "198.51.100.23",
        "abuseConfidenceScore": 95,
        "categories": [18, 22, 15],
        "countryCode": "RU",
        "totalReports": 487,
        "isp": "Shady Hosting Inc.",
        "domain": "shadyhosting.ru",
    },
    "203.0.113.42": {
        "ipAddress": "203.0.113.42",
        "abuseConfidenceScore": 88,
        "categories": [14, 15, 21],
        "countryCode": "CN",
        "totalReports": 312,
        "isp": "Chinanet",
        "domain": "chinanet.cn",
    },
    "203.0.113.99": {
        "ipAddress": "203.0.113.99",
        "abuseConfidenceScore": 76,
        "categories": [8, 21],
        "countryCode": "NG",
        "totalReports": 145,
        "isp": "NigeriaNet",
        "domain": "nignet.ng",
    },
}

# ======================================================================
# AlienVault OTX mock data
# ======================================================================
MOCK_OTX_PULSES: list[dict] = [
    {
        "name": "Mirai Botnet C2 Infrastructure - March 2026",
        "tags": ["mirai", "botnet", "iot", "c2"],
        "indicators": [
            {"indicator": "198.51.100.23", "type": "IPv4", "created": "2026-03-20T10:00:00"},
            {"indicator": "malware-c2.evil.xyz", "type": "domain", "created": "2026-03-20T10:00:00"},
            {"indicator": "http://198.51.100.23:8080/bins/mirai.arm7", "type": "URL", "created": "2026-03-20T10:00:00"},
            {"indicator": "e99a18c428cb38d5f260853678922e03", "type": "FileHash-MD5", "created": "2026-03-20T10:00:00"},
        ],
    },
    {
        "name": "Credential Phishing Campaign - Q1 2026",
        "tags": ["phishing", "credential-theft", "social-engineering"],
        "indicators": [
            {"indicator": "203.0.113.99", "type": "IPv4", "created": "2026-03-18T14:30:00"},
            {"indicator": "phish-login.badactor.top", "type": "domain", "created": "2026-03-18T14:30:00"},
            {"indicator": "https://phish-login.badactor.top/wp-login.php", "type": "URL", "created": "2026-03-18T14:30:00"},
        ],
    },
    {
        "name": "Ransomware Dropper Network",
        "tags": ["ransomware", "dropper", "malware"],
        "indicators": [
            {"indicator": "203.0.113.42", "type": "IPv4", "created": "2026-03-15T08:00:00"},
            {"indicator": "dropper.darknet.ru", "type": "domain", "created": "2026-03-15T08:00:00"},
            {"indicator": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "type": "FileHash-SHA256", "created": "2026-03-15T08:00:00"},
            {"indicator": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "type": "FileHash-SHA1", "created": "2026-03-15T08:00:00"},
        ],
    },
]

MOCK_OTX_GENERAL: dict[str, dict] = {
    "198.51.100.23": {
        "pulse_info": {
            "count": 7,
            "pulses": [
                {"name": "Mirai C2", "tags": ["mirai", "botnet"]},
                {"name": "SSH Brute Force", "tags": ["ssh", "brute-force"]},
            ],
        },
    },
    "malware-c2.evil.xyz": {
        "pulse_info": {
            "count": 4,
            "pulses": [
                {"name": "Mirai C2", "tags": ["mirai", "c2"]},
            ],
        },
    },
}

# ======================================================================
# URLhaus mock data
# ======================================================================
MOCK_URLHAUS_RECENT: list[dict] = [
    {
        "url": "http://198.51.100.23:8080/bins/mirai.arm7",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["mirai", "elf", "arm"],
        "date_added": "2026-03-22 09:15:00",
        "host": "198.51.100.23",
    },
    {
        "url": "http://malware-c2.evil.xyz/gate.php",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["trojan", "c2"],
        "date_added": "2026-03-21 17:30:00",
        "host": "malware-c2.evil.xyz",
    },
    {
        "url": "https://phish-login.badactor.top/wp-login.php",
        "url_status": "online",
        "threat": "phishing",
        "tags": ["phishing", "wordpress"],
        "date_added": "2026-03-20 11:00:00",
        "host": "phish-login.badactor.top",
    },
    {
        "url": "http://203.0.113.42:443/payload.exe",
        "url_status": "offline",
        "threat": "malware_download",
        "tags": ["ransomware", "exe"],
        "date_added": "2026-03-19 06:45:00",
        "host": "203.0.113.42",
    },
    {
        "url": "http://198.51.100.77/loader.sh",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["cryptominer", "shell"],
        "date_added": "2026-03-18 22:00:00",
        "host": "198.51.100.77",
    },
]

MOCK_URLHAUS_HOST_LOOKUP: dict[str, dict] = {
    "198.51.100.23": {
        "url_count": 12,
        "urls_online": 3,
        "urls": [
            {"tags": ["mirai", "elf"]},
            {"tags": ["botnet", "arm"]},
        ],
    },
    "malware-c2.evil.xyz": {
        "url_count": 5,
        "urls_online": 2,
        "urls": [
            {"tags": ["trojan", "c2"]},
        ],
    },
}

# ======================================================================
# Emerging Threats mock data
# ======================================================================
MOCK_ET_BLOCKLIST_IPS: list[str] = [
    "# Emerging Threats compromised IPs (mock)",
    "198.51.100.23",
    "203.0.113.42",
    "198.51.100.77",
    "203.0.113.99",
    "192.0.2.15",
    "198.51.100.200",
    "203.0.113.150",
    "198.51.100.55",
    "203.0.113.10",
    "192.0.2.88",
    "198.51.100.130",
    "203.0.113.201",
]
