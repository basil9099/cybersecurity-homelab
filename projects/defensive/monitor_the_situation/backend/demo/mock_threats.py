"""Generate IP-based threat events distributed across 20+ countries over the last 24h."""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Country -> (IP prefix, cities with lat/lon, ASN examples)
# We use TEST-NET / documentation ranges conceptually but generate IPs that
# *look* public.  The geo mapping is deterministic via mock_geo.
# ---------------------------------------------------------------------------
_COUNTRY_DATA: list[dict] = [
    {"cc": "CN", "weight": 18, "cities": [("Beijing", 39.90, 116.40), ("Shanghai", 31.23, 121.47), ("Shenzhen", 22.54, 114.06)],
     "asns": ["AS4134 ChinaNet", "AS4837 CNCGROUP", "AS9808 China Mobile"]},
    {"cc": "RU", "weight": 14, "cities": [("Moscow", 55.75, 37.62), ("Saint Petersburg", 59.93, 30.32), ("Novosibirsk", 55.04, 82.93)],
     "asns": ["AS12389 Rostelecom", "AS8402 VEON", "AS31133 MegaFon"]},
    {"cc": "US", "weight": 12, "cities": [("Ashburn", 39.04, -77.49), ("Dallas", 32.78, -96.80), ("San Jose", 37.34, -121.89)],
     "asns": ["AS14618 Amazon", "AS15169 Google", "AS13335 Cloudflare"]},
    {"cc": "BR", "weight": 8, "cities": [("São Paulo", -23.55, -46.63), ("Rio de Janeiro", -22.91, -43.17)],
     "asns": ["AS28573 Claro", "AS18881 Vivo"]},
    {"cc": "IN", "weight": 7, "cities": [("Mumbai", 19.08, 72.88), ("Bangalore", 12.97, 77.59), ("Delhi", 28.61, 77.21)],
     "asns": ["AS9498 Bharti Airtel", "AS55836 Reliance Jio"]},
    {"cc": "DE", "weight": 5, "cities": [("Frankfurt", 50.11, 8.68), ("Berlin", 52.52, 13.41)],
     "asns": ["AS3320 Deutsche Telekom", "AS6805 Telefonica Germany"]},
    {"cc": "NL", "weight": 5, "cities": [("Amsterdam", 52.37, 4.90), ("Rotterdam", 51.92, 4.48)],
     "asns": ["AS60781 LeaseWeb", "AS49981 WorldStream"]},
    {"cc": "KR", "weight": 4, "cities": [("Seoul", 37.57, 126.98), ("Busan", 35.18, 129.08)],
     "asns": ["AS4766 Korea Telecom", "AS9318 SK Broadband"]},
    {"cc": "VN", "weight": 4, "cities": [("Hanoi", 21.03, 105.85), ("Ho Chi Minh City", 10.82, 106.63)],
     "asns": ["AS45899 VNPT", "AS7552 Viettel"]},
    {"cc": "UA", "weight": 3, "cities": [("Kyiv", 50.45, 30.52), ("Kharkiv", 49.99, 36.23)],
     "asns": ["AS15895 Kyivstar", "AS13249 DataGroup"]},
    {"cc": "IR", "weight": 3, "cities": [("Tehran", 35.69, 51.39), ("Isfahan", 32.65, 51.68)],
     "asns": ["AS44244 Irancell", "AS197207 MCCI"]},
    {"cc": "ID", "weight": 3, "cities": [("Jakarta", -6.21, 106.85)],
     "asns": ["AS17974 Telkomnet"]},
    {"cc": "TR", "weight": 2, "cities": [("Istanbul", 41.01, 28.98), ("Ankara", 39.93, 32.86)],
     "asns": ["AS9121 Turk Telekom"]},
    {"cc": "PL", "weight": 2, "cities": [("Warsaw", 52.23, 21.01)],
     "asns": ["AS5617 Orange Polska"]},
    {"cc": "TH", "weight": 2, "cities": [("Bangkok", 13.76, 100.50)],
     "asns": ["AS23969 TOT"]},
    {"cc": "PK", "weight": 2, "cities": [("Karachi", 24.86, 67.01), ("Lahore", 31.55, 74.34)],
     "asns": ["AS17557 PTCL"]},
    {"cc": "AR", "weight": 1, "cities": [("Buenos Aires", -34.60, -58.38)],
     "asns": ["AS7303 Telecom Argentina"]},
    {"cc": "NG", "weight": 1, "cities": [("Lagos", 6.52, 3.38)],
     "asns": ["AS37148 Nigeria Internet"]},
    {"cc": "RO", "weight": 1, "cities": [("Bucharest", 44.43, 26.10)],
     "asns": ["AS8708 RCS-RDS"]},
    {"cc": "SG", "weight": 1, "cities": [("Singapore", 1.35, 103.82)],
     "asns": ["AS4657 StarHub"]},
    {"cc": "FR", "weight": 1, "cities": [("Paris", 48.86, 2.35)],
     "asns": ["AS3215 Orange France"]},
    {"cc": "GB", "weight": 1, "cities": [("London", 51.51, -0.13)],
     "asns": ["AS2856 BT"]},
    {"cc": "JP", "weight": 1, "cities": [("Tokyo", 35.68, 139.69)],
     "asns": ["AS2516 KDDI"]},
    {"cc": "ZA", "weight": 1, "cities": [("Johannesburg", -26.20, 28.04)],
     "asns": ["AS37457 Telkom SA"]},
    {"cc": "MX", "weight": 1, "cities": [("Mexico City", 19.43, -99.13)],
     "asns": ["AS8151 Telmex"]},
]

_CATEGORIES = ["scanner", "brute_force", "malware", "exploitation", "botnet", "spam"]
_SOURCES = ["greynoise", "abuseipdb", "otx"]

_TAGS_BY_CATEGORY = {
    "scanner":      ["ssh-scanner", "port-scanner", "web-crawler", "vuln-scanner", "masscan"],
    "brute_force":  ["ssh-brute", "rdp-brute", "smtp-brute", "ftp-brute", "credential-stuffing"],
    "malware":      ["mirai-variant", "mozi-bot", "emotet-c2", "cobalt-strike", "raccoon-stealer"],
    "exploitation": ["log4shell", "cve-exploit", "webshell-upload", "rce-attempt", "sqli-probe"],
    "botnet":       ["mirai-drone", "hajime-node", "tor-exit-node", "proxy-bot", "ddos-reflector"],
    "spam":         ["spam-relay", "phishing-sender", "backscatter", "newsletter-abuse"],
}


def _make_ip(rng: random.Random, index: int) -> str:
    """Generate a realistic-looking IP.  Avoids reserved ranges."""
    # Spread across different first octets that look public
    first_octets = [45, 51, 62, 77, 91, 103, 112, 128, 141, 154, 167, 176, 185, 193, 203, 212, 218, 223]
    a = rng.choice(first_octets)
    b = rng.randint(0, 255)
    c = rng.randint(0, 255)
    d = rng.randint(1, 254)
    return f"{a}.{b}.{c}.{d}"


def generate_threats(count: int = 200, seed: int = 42) -> list[dict]:
    """Return *count* threat-event dicts ready for the threat_events table."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)

    # Build weighted country pool
    country_pool: list[dict] = []
    for cd in _COUNTRY_DATA:
        country_pool.extend([cd] * cd["weight"])

    records: list[dict] = []

    for i in range(count):
        cd = rng.choice(country_pool)
        city_name, lat, lon = rng.choice(cd["cities"])
        # Jitter coordinates slightly
        lat += rng.gauss(0, 0.05)
        lon += rng.gauss(0, 0.05)

        ip = _make_ip(rng, i)
        category = rng.choice(_CATEGORIES)
        source = rng.choice(_SOURCES)
        tags = rng.sample(_TAGS_BY_CATEGORY[category], k=rng.randint(1, min(3, len(_TAGS_BY_CATEGORY[category]))))
        confidence = round(rng.uniform(0.3, 1.0), 2)

        # Distribute over last 24h with heavier concentration in recent hours
        # Use an exponential-ish distribution: more events closer to now
        hours_ago = rng.expovariate(0.25)  # mean ~4 hours ago
        hours_ago = min(hours_ago, 24.0)
        event_time = now - timedelta(hours=hours_ago)
        first_seen = event_time - timedelta(minutes=rng.randint(0, 120))

        event_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"threat-{ip}-{i}-{seed}"))

        records.append({
            "id": event_id,
            "source": source,
            "ip": ip,
            "country": cd["cc"],
            "city": city_name,
            "latitude": round(lat, 4),
            "longitude": round(lon, 4),
            "asn": rng.choice(cd["asns"]).split()[0],
            "asn_org": rng.choice(cd["asns"]),
            "category": category,
            "confidence": confidence,
            "tags": tags,
            "first_seen": first_seen.isoformat(),
            "last_seen": event_time.isoformat(),
            "raw_data": {},
        })

    records.sort(key=lambda r: r["last_seen"], reverse=True)
    return records
