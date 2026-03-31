"""Application configuration via environment variables with sensible defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


@dataclass
class Settings:
    """Central configuration.  Reads from env vars with ``MTS_`` prefix."""

    # General
    debug: bool = False
    demo_mode: bool = False
    db_path: Path = DATA_DIR / "monitor.db"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # API keys (all optional -- demo mode used when absent)
    nvd_api_key: str = ""
    greynoise_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    shodan_api_key: str = ""
    github_token: str = ""

    # GeoIP
    geoip_db_path: str = ""

    # Mastodon
    mastodon_instance: str = "https://infosec.exchange"

    # RSS feeds (semicolon-separated list of URLs)
    rss_feed_urls: str = (
        "https://feeds.feedburner.com/TheHackersNews;"
        "https://www.bleepingcomputer.com/feed/;"
        "https://krebsonsecurity.com/feed/;"
        "https://blog.talosintelligence.com/rss/;"
        "https://www.darkreading.com/rss.xml"
    )

    # Scheduler intervals (seconds)
    interval_cve: int = 900        # 15 minutes
    interval_threat_feeds: int = 3600  # 1 hour
    interval_exploits: int = 1800  # 30 minutes
    interval_social: int = 300     # 5 minutes
    interval_mitre: int = 86400    # 24 hours

    # Demo scheduler intervals (faster)
    demo_interval_cve: int = 30
    demo_interval_threat_feeds: int = 10
    demo_interval_exploits: int = 20
    demo_interval_social: int = 10
    demo_interval_mitre: int = 0  # startup only

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from environment variables with ``MTS_`` prefix."""
        kwargs: dict = {}
        for f_name, f_obj in cls.__dataclass_fields__.items():
            env_key = f"MTS_{f_name.upper()}"
            env_val = os.environ.get(env_key)
            if env_val is not None:
                f_type = f_obj.type
                if f_type == "bool":
                    kwargs[f_name] = env_val.lower() in ("1", "true", "yes")
                elif f_type == "int":
                    kwargs[f_name] = int(env_val)
                elif "Path" in str(f_type):
                    kwargs[f_name] = Path(env_val)
                else:
                    kwargs[f_name] = env_val
        return cls(**kwargs)

    @property
    def has_api_keys(self) -> bool:
        return any([
            self.nvd_api_key,
            self.greynoise_api_key,
            self.abuseipdb_api_key,
            self.otx_api_key,
        ])

    @property
    def rss_feeds(self) -> list[str]:
        return [u.strip() for u in self.rss_feed_urls.split(";") if u.strip()]
