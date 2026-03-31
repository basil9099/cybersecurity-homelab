"""Deterministic IP-to-geolocation mapping for demo mode."""

from __future__ import annotations

import hashlib

_LOCATIONS = [
    ("CN", "Beijing", 39.9042, 116.4074, "AS4134", "China Telecom"),
    ("CN", "Shanghai", 31.2304, 121.4737, "AS4812", "China Telecom"),
    ("RU", "Moscow", 55.7558, 37.6173, "AS12389", "Rostelecom"),
    ("US", "Ashburn", 39.0438, -77.4874, "AS14618", "Amazon AWS"),
    ("US", "San Jose", 37.3382, -121.8863, "AS36351", "SoftLayer"),
    ("US", "Dallas", 32.7767, -96.7970, "AS33070", "Rackspace"),
    ("BR", "Sao Paulo", -23.5505, -46.6333, "AS28573", "Claro"),
    ("IN", "Mumbai", 19.0760, 72.8777, "AS9829", "BSNL"),
    ("DE", "Frankfurt", 50.1109, 8.6821, "AS3320", "Deutsche Telekom"),
    ("NL", "Amsterdam", 52.3676, 4.9041, "AS60781", "LeaseWeb"),
    ("KR", "Seoul", 37.5665, 126.9780, "AS4766", "Korea Telecom"),
    ("VN", "Hanoi", 21.0278, 105.8342, "AS45899", "VNPT"),
    ("UA", "Kyiv", 50.4501, 30.5234, "AS13249", "PrivatBank"),
    ("IR", "Tehran", 35.6892, 51.3890, "AS44244", "Irancell"),
    ("GB", "London", 51.5074, -0.1278, "AS5089", "Virgin Media"),
    ("FR", "Paris", 48.8566, 2.3522, "AS3215", "Orange"),
    ("JP", "Tokyo", 35.6762, 139.6503, "AS2516", "KDDI"),
    ("AU", "Sydney", -33.8688, 151.2093, "AS7545", "TPG"),
    ("CA", "Toronto", 43.6532, -79.3832, "AS812", "Rogers"),
    ("SG", "Singapore", 1.3521, 103.8198, "AS4773", "SingTel"),
    ("IL", "Tel Aviv", 32.0853, 34.7818, "AS8551", "Bezeq"),
    ("PL", "Warsaw", 52.2297, 21.0122, "AS5617", "Orange Polska"),
    ("TW", "Taipei", 25.0330, 121.5654, "AS3462", "HiNet"),
    ("AR", "Buenos Aires", -34.6037, -58.3816, "AS7303", "Telecom Argentina"),
    ("ZA", "Johannesburg", -26.2041, 28.0473, "AS37457", "Telkom SA"),
]


def lookup_ip(ip: str) -> dict:
    """Deterministic geolocation lookup for any IP."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    loc = _LOCATIONS[h % len(_LOCATIONS)]
    country, city, lat, lon, asn, asn_org = loc
    return {
        "country": country,
        "city": city,
        "latitude": lat,
        "longitude": lon,
        "asn": asn,
        "asn_org": asn_org,
    }
