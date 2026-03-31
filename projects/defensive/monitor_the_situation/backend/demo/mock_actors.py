"""Mock APT groups with MITRE ATT&CK TTPs."""

from __future__ import annotations

from datetime import datetime, timezone

_ACTORS = [
    {
        "id": "G0007",
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
        "description": "Russian state-sponsored group attributed to GRU Unit 26165. Active since 2004, targeting government, military, and security organizations.",
        "country_origin": "RU",
        "first_seen": "2004-01-01",
        "last_seen": "2026-02-15",
        "target_sectors": ["government", "military", "defense", "media", "energy"],
        "target_countries": ["US", "UA", "DE", "FR", "GB", "GE", "PL"],
        "sophistication": "advanced",
        "campaign_count": 42,
        "technique_count": 58,
        "ttps": [
            ("T1566.001", "Spearphishing Attachment", "initial-access", 15),
            ("T1059.001", "PowerShell", "execution", 12),
            ("T1078", "Valid Accounts", "persistence", 8),
            ("T1071.001", "Web Protocols", "command-and-control", 10),
            ("T1027", "Obfuscated Files or Information", "defense-evasion", 9),
            ("T1083", "File and Directory Discovery", "discovery", 7),
            ("T1560.001", "Archive via Utility", "collection", 5),
            ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "exfiltration", 6),
        ],
    },
    {
        "id": "G0016",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
        "description": "Russian state-sponsored group attributed to SVR. Known for SolarWinds supply chain attack and sophisticated espionage campaigns.",
        "country_origin": "RU",
        "first_seen": "2008-01-01",
        "last_seen": "2026-03-01",
        "target_sectors": ["government", "technology", "think-tanks", "healthcare"],
        "target_countries": ["US", "GB", "DE", "NL", "NO", "CZ"],
        "sophistication": "advanced",
        "campaign_count": 35,
        "technique_count": 52,
        "ttps": [
            ("T1195.002", "Compromise Software Supply Chain", "initial-access", 8),
            ("T1059.001", "PowerShell", "execution", 11),
            ("T1098", "Account Manipulation", "persistence", 7),
            ("T1550.001", "Application Access Token", "lateral-movement", 6),
            ("T1587.001", "Malware", "resource-development", 9),
            ("T1070.004", "File Deletion", "defense-evasion", 5),
            ("T1114.002", "Remote Email Collection", "collection", 8),
        ],
    },
    {
        "id": "G0032",
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Zinc", "Diamond Sleet"],
        "description": "North Korean state-sponsored group responsible for WannaCry, Bangladesh Bank heist, and numerous cryptocurrency thefts.",
        "country_origin": "KP",
        "first_seen": "2009-01-01",
        "last_seen": "2026-03-10",
        "target_sectors": ["financial", "cryptocurrency", "defense", "entertainment", "technology"],
        "target_countries": ["US", "KR", "JP", "IN", "GB", "PH"],
        "sophistication": "advanced",
        "campaign_count": 48,
        "technique_count": 61,
        "ttps": [
            ("T1566.002", "Spearphishing Link", "initial-access", 14),
            ("T1059.006", "Python", "execution", 8),
            ("T1543.003", "Windows Service", "persistence", 6),
            ("T1055.001", "Dynamic-link Library Injection", "defense-evasion", 7),
            ("T1486", "Data Encrypted for Impact", "impact", 5),
            ("T1657", "Financial Theft", "impact", 12),
            ("T1071.001", "Web Protocols", "command-and-control", 9),
        ],
    },
    {
        "id": "G0096",
        "name": "APT41",
        "aliases": ["Winnti", "Wicked Panda", "Barium"],
        "description": "Chinese state-sponsored group conducting both espionage and financially motivated operations. Unique dual-mission threat actor.",
        "country_origin": "CN",
        "first_seen": "2012-01-01",
        "last_seen": "2026-02-20",
        "target_sectors": ["technology", "healthcare", "gaming", "telecommunications", "education"],
        "target_countries": ["US", "GB", "FR", "AU", "JP", "IN", "DE"],
        "sophistication": "advanced",
        "campaign_count": 38,
        "technique_count": 55,
        "ttps": [
            ("T1190", "Exploit Public-Facing Application", "initial-access", 11),
            ("T1059.003", "Windows Command Shell", "execution", 9),
            ("T1574.001", "DLL Search Order Hijacking", "persistence", 7),
            ("T1055", "Process Injection", "defense-evasion", 8),
            ("T1021.001", "Remote Desktop Protocol", "lateral-movement", 6),
            ("T1005", "Data from Local System", "collection", 5),
        ],
    },
    {
        "id": "G0058",
        "name": "Charming Kitten",
        "aliases": ["APT35", "Phosphorus", "Mint Sandstorm", "TA453"],
        "description": "Iranian state-sponsored group targeting academics, journalists, diplomats, and human rights activists.",
        "country_origin": "IR",
        "first_seen": "2014-01-01",
        "last_seen": "2026-01-25",
        "target_sectors": ["government", "academia", "media", "human-rights", "defense"],
        "target_countries": ["US", "IL", "GB", "SA", "AE"],
        "sophistication": "high",
        "campaign_count": 25,
        "technique_count": 38,
        "ttps": [
            ("T1566.001", "Spearphishing Attachment", "initial-access", 13),
            ("T1204.002", "Malicious File", "execution", 10),
            ("T1555.003", "Credentials from Web Browsers", "credential-access", 7),
            ("T1534", "Internal Spearphishing", "lateral-movement", 4),
            ("T1102", "Web Service", "command-and-control", 6),
        ],
    },
    {
        "id": "G0034",
        "name": "Sandworm",
        "aliases": ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "TeleBots"],
        "description": "Russian GRU Unit 74455. Responsible for NotPetya, attacks on Ukrainian power grid, and Olympic Destroyer.",
        "country_origin": "RU",
        "first_seen": "2009-01-01",
        "last_seen": "2026-03-05",
        "target_sectors": ["energy", "government", "critical-infrastructure", "media", "transportation"],
        "target_countries": ["UA", "US", "GB", "GE", "PL", "KR"],
        "sophistication": "advanced",
        "campaign_count": 30,
        "technique_count": 45,
        "ttps": [
            ("T1190", "Exploit Public-Facing Application", "initial-access", 9),
            ("T1059.001", "PowerShell", "execution", 8),
            ("T1485", "Data Destruction", "impact", 7),
            ("T1489", "Service Stop", "impact", 6),
            ("T1562.001", "Disable or Modify Tools", "defense-evasion", 5),
            ("T1021.002", "SMB/Windows Admin Shares", "lateral-movement", 8),
        ],
    },
    {
        "id": "G0010",
        "name": "Turla",
        "aliases": ["Snake", "Venomous Bear", "Waterbug", "Secret Blizzard"],
        "description": "Sophisticated Russian espionage group linked to FSB. Known for satellite-based C2 channels and hijacking other groups' infrastructure.",
        "country_origin": "RU",
        "first_seen": "1996-01-01",
        "last_seen": "2026-01-30",
        "target_sectors": ["government", "diplomatic", "military", "research"],
        "target_countries": ["US", "DE", "FR", "GB", "BE", "UA", "KZ"],
        "sophistication": "advanced",
        "campaign_count": 28,
        "technique_count": 50,
        "ttps": [
            ("T1189", "Drive-by Compromise", "initial-access", 6),
            ("T1059.005", "Visual Basic", "execution", 7),
            ("T1547.001", "Registry Run Keys", "persistence", 8),
            ("T1090.003", "Multi-hop Proxy", "command-and-control", 5),
            ("T1001.001", "Junk Data", "command-and-control", 4),
            ("T1016", "System Network Configuration Discovery", "discovery", 6),
        ],
    },
    {
        "id": "G0045",
        "name": "APT10",
        "aliases": ["Stone Panda", "menuPass", "Red Apollo"],
        "description": "Chinese state-sponsored group targeting managed service providers for supply chain compromise and intellectual property theft.",
        "country_origin": "CN",
        "first_seen": "2006-01-01",
        "last_seen": "2025-12-15",
        "target_sectors": ["technology", "msp", "engineering", "healthcare", "aerospace"],
        "target_countries": ["US", "JP", "GB", "AU", "CA", "IN"],
        "sophistication": "high",
        "campaign_count": 22,
        "technique_count": 35,
        "ttps": [
            ("T1199", "Trusted Relationship", "initial-access", 9),
            ("T1059.001", "PowerShell", "execution", 7),
            ("T1078", "Valid Accounts", "persistence", 8),
            ("T1090.002", "External Proxy", "command-and-control", 5),
            ("T1560", "Archive Collected Data", "collection", 6),
        ],
    },
    {
        "id": "G0094",
        "name": "Kimsuky",
        "aliases": ["Velvet Chollima", "Thallium", "Black Banshee"],
        "description": "North Korean group focused on intelligence gathering targeting think tanks, academia, and government organizations.",
        "country_origin": "KP",
        "first_seen": "2012-01-01",
        "last_seen": "2026-02-28",
        "target_sectors": ["government", "academia", "think-tanks", "defense", "nuclear"],
        "target_countries": ["KR", "US", "JP", "DE", "GB"],
        "sophistication": "high",
        "campaign_count": 20,
        "technique_count": 32,
        "ttps": [
            ("T1566.001", "Spearphishing Attachment", "initial-access", 11),
            ("T1204.001", "Malicious Link", "execution", 8),
            ("T1555", "Credentials from Password Stores", "credential-access", 6),
            ("T1105", "Ingress Tool Transfer", "command-and-control", 5),
            ("T1113", "Screen Capture", "collection", 4),
        ],
    },
    {
        "id": "G0069",
        "name": "MuddyWater",
        "aliases": ["MERCURY", "Mango Sandstorm", "Static Kitten"],
        "description": "Iranian MOIS-affiliated group targeting government and telecommunications sectors across the Middle East and Central Asia.",
        "country_origin": "IR",
        "first_seen": "2017-01-01",
        "last_seen": "2026-01-15",
        "target_sectors": ["government", "telecommunications", "oil-gas", "defense"],
        "target_countries": ["SA", "IQ", "IL", "TR", "AE", "PK", "IN"],
        "sophistication": "medium",
        "campaign_count": 18,
        "technique_count": 28,
        "ttps": [
            ("T1566.001", "Spearphishing Attachment", "initial-access", 10),
            ("T1059.001", "PowerShell", "execution", 9),
            ("T1547.001", "Registry Run Keys", "persistence", 5),
            ("T1218.005", "Mshta", "defense-evasion", 6),
            ("T1071.001", "Web Protocols", "command-and-control", 7),
        ],
    },
]


def _rank_score(actor: dict) -> float:
    soph_map = {"low": 2.0, "medium": 5.0, "high": 7.5, "advanced": 10.0}
    soph = soph_map.get(actor["sophistication"], 5.0)
    return round(
        actor["campaign_count"] * 0.4
        + actor["technique_count"] * 0.3
        + soph * 0.3,
        2,
    )


def generate_mock_actors() -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    records = []
    for a in _ACTORS:
        records.append({
            "id": a["id"],
            "name": a["name"],
            "aliases": a["aliases"],
            "description": a["description"],
            "country_origin": a["country_origin"],
            "first_seen": a["first_seen"],
            "last_seen": a["last_seen"],
            "target_sectors": a["target_sectors"],
            "target_countries": a["target_countries"],
            "sophistication": a["sophistication"],
            "campaign_count": a["campaign_count"],
            "technique_count": a["technique_count"],
            "rank_score": _rank_score(a),
            "updated_at": now,
        })
    return records


def generate_mock_ttps() -> list[dict]:
    records = []
    for a in _ACTORS:
        for tid, tname, tactic, usage in a["ttps"]:
            records.append({
                "actor_id": a["id"],
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
                "usage_count": usage,
            })
    return records
