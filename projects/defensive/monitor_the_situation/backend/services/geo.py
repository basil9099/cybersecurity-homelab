"""IP geolocation service using MaxMind GeoLite2 with mock fallback."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("mts.services.geo")


class GeoIPService:
    def __init__(self, geoip_db_path: str = "", demo_mode: bool = False) -> None:
        self.demo_mode = demo_mode
        self._reader = None

        if not demo_mode and geoip_db_path:
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(geoip_db_path)
                logger.info("Loaded MaxMind GeoIP database from %s", geoip_db_path)
            except Exception as e:
                logger.warning("Could not load GeoIP database: %s (using mock)", e)

    def lookup(self, ip: str) -> dict[str, Any] | None:
        if self._reader:
            return self._lookup_maxmind(ip)
        return self._lookup_mock(ip)

    def _lookup_maxmind(self, ip: str) -> dict[str, Any] | None:
        try:
            resp = self._reader.city(ip)
            return {
                "country": resp.country.iso_code,
                "city": resp.city.name,
                "latitude": resp.location.latitude,
                "longitude": resp.location.longitude,
                "asn": None,
                "asn_org": None,
            }
        except Exception:
            return self._lookup_mock(ip)

    def _lookup_mock(self, ip: str) -> dict[str, Any]:
        from backend.demo.mock_geo import lookup_ip
        return lookup_ip(ip)

    def close(self) -> None:
        if self._reader:
            self._reader.close()
