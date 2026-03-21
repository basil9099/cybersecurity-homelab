#!/usr/bin/env python3
"""
collector/aggregator.py
=======================
Aggregates raw packet lists into per-window traffic statistics.

A TrafficWindow summarises all traffic within a fixed time interval:
total bytes/packets, per-protocol breakdown, top-talkers, port distribution,
external outbound bytes, and internal east-west pairs.
"""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from collector.sniffer import RawPacket


# RFC 1918 private address spaces
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_private(ip_str: str) -> bool:
    """Return True if the IP address is in a private (RFC 1918) range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


@dataclass
class TrafficWindow:
    """Aggregated traffic statistics for a single time window."""

    # Window metadata
    timestamp: float          = field(default_factory=time.time)
    window_seconds: int       = 60

    # Volume metrics
    total_bytes: int          = 0
    total_packets: int        = 0

    # Protocol breakdown: {"TCP": bytes, "UDP": bytes, ...}
    bytes_per_protocol: dict[str, int] = field(default_factory=dict)
    pkts_per_protocol: dict[str, int]  = field(default_factory=dict)

    # Unique IP counts
    unique_src_ips: int       = 0
    unique_dst_ips: int       = 0

    # Top talkers: src_ip -> bytes sent (top 10)
    top_talkers: dict[str, int] = field(default_factory=dict)

    # Port counts: dst_port -> connection count (top 20)
    port_counts: dict[str, int] = field(default_factory=dict)

    # Per-source port spread: src_ip -> set of dst_ports (for port scan detection)
    src_port_spread: dict[str, list[int]] = field(default_factory=dict)

    # Outbound bytes to external IPs (private src -> public dst)
    external_bytes_out: int   = 0

    # External destinations: dst_ip -> bytes (for exfil detection)
    external_dst_bytes: dict[str, int] = field(default_factory=dict)

    # Internal east-west pairs: "src_ip:dst_ip" -> packet_count
    internal_pairs: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (JSON-safe)."""
        return {
            "timestamp": self.timestamp,
            "window_seconds": self.window_seconds,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "bytes_per_protocol": self.bytes_per_protocol,
            "pkts_per_protocol": self.pkts_per_protocol,
            "unique_src_ips": self.unique_src_ips,
            "unique_dst_ips": self.unique_dst_ips,
            "top_talkers": self.top_talkers,
            "port_counts": self.port_counts,
            "src_port_spread": {k: v for k, v in self.src_port_spread.items()},
            "external_bytes_out": self.external_bytes_out,
            "external_dst_bytes": self.external_dst_bytes,
            "internal_pairs": self.internal_pairs,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TrafficWindow":
        """Deserialise from a plain dict."""
        w = cls()
        w.timestamp = d.get("timestamp", 0.0)
        w.window_seconds = d.get("window_seconds", 60)
        w.total_bytes = d.get("total_bytes", 0)
        w.total_packets = d.get("total_packets", 0)
        w.bytes_per_protocol = d.get("bytes_per_protocol", {})
        w.pkts_per_protocol = d.get("pkts_per_protocol", {})
        w.unique_src_ips = d.get("unique_src_ips", 0)
        w.unique_dst_ips = d.get("unique_dst_ips", 0)
        w.top_talkers = d.get("top_talkers", {})
        w.port_counts = d.get("port_counts", {})
        w.src_port_spread = d.get("src_port_spread", {})
        w.external_bytes_out = d.get("external_bytes_out", 0)
        w.external_dst_bytes = d.get("external_dst_bytes", {})
        w.internal_pairs = d.get("internal_pairs", {})
        return w


def aggregate(
    packets: list[RawPacket],
    window_seconds: int = 60,
    timestamp: float | None = None,
    top_n_talkers: int = 10,
    top_n_ports: int = 20,
) -> TrafficWindow:
    """
    Aggregate a list of raw packets into a TrafficWindow.

    Args:
        packets:        Raw packets to aggregate (all assumed within one window).
        window_seconds: Duration of the window in seconds.
        timestamp:      Window start time (defaults to earliest packet timestamp).
        top_n_talkers:  How many top source IPs to retain.
        top_n_ports:    How many top destination ports to retain.

    Returns:
        A populated TrafficWindow.
    """
    if not packets:
        ts = timestamp or time.time()
        return TrafficWindow(timestamp=ts, window_seconds=window_seconds)

    ts = timestamp or min(p.timestamp for p in packets)

    bytes_proto: dict[str, int] = defaultdict(int)
    pkts_proto: dict[str, int] = defaultdict(int)
    src_bytes: dict[str, int] = defaultdict(int)
    dst_port_counts: dict[str, int] = defaultdict(int)
    src_port_sets: dict[str, set] = defaultdict(set)
    ext_dst_bytes: dict[str, int] = defaultdict(int)
    int_pairs: dict[str, int] = defaultdict(int)
    src_ips: set[str] = set()
    dst_ips: set[str] = set()
    total_bytes = 0
    external_out = 0

    for pkt in packets:
        total_bytes += pkt.length
        bytes_proto[pkt.protocol] += pkt.length
        pkts_proto[pkt.protocol] += 1
        src_bytes[pkt.src_ip] += pkt.length
        src_ips.add(pkt.src_ip)
        dst_ips.add(pkt.dst_ip)

        if pkt.dst_port > 0:
            dst_port_counts[str(pkt.dst_port)] += 1

        if pkt.dst_port > 0 or pkt.src_port > 0:
            src_port_sets[pkt.src_ip].add(pkt.dst_port)

        src_private = _is_private(pkt.src_ip)
        dst_private = _is_private(pkt.dst_ip)

        if src_private and not dst_private:
            external_out += pkt.length
            ext_dst_bytes[pkt.dst_ip] += pkt.length

        if src_private and dst_private and pkt.src_ip != pkt.dst_ip:
            pair_key = f"{pkt.src_ip}:{pkt.dst_ip}"
            int_pairs[pair_key] += 1

    # Trim to top-N entries
    top_talkers = dict(
        sorted(src_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n_talkers]
    )
    top_ports = dict(
        sorted(dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:top_n_ports]
    )
    top_ext_dst = dict(
        sorted(ext_dst_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n_ports]
    )

    # Convert port sets to sorted lists for JSON serialisation
    port_spread = {ip: sorted(ports) for ip, ports in src_port_sets.items()}

    return TrafficWindow(
        timestamp=ts,
        window_seconds=window_seconds,
        total_bytes=total_bytes,
        total_packets=len(packets),
        bytes_per_protocol=dict(bytes_proto),
        pkts_per_protocol=dict(pkts_proto),
        unique_src_ips=len(src_ips),
        unique_dst_ips=len(dst_ips),
        top_talkers=top_talkers,
        port_counts=top_ports,
        src_port_spread=port_spread,
        external_bytes_out=external_out,
        external_dst_bytes=top_ext_dst,
        internal_pairs=dict(int_pairs),
    )
