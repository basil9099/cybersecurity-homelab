#!/usr/bin/env python3
"""
collector/sniffer.py
====================
Packet capture module using scapy or PCAP file reading.

Extracts per-packet statistics for downstream aggregation.
Supports live capture (requires root) and offline PCAP analysis.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Scapy import with graceful failure for environments where it's unavailable
try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class RawPacket:
    """Normalised representation of a single captured packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str          # TCP | UDP | ICMP | Other
    src_port: int
    dst_port: int
    length: int            # bytes (IP total length)


def _extract_packet(pkt) -> RawPacket | None:
    """Convert a scapy packet to RawPacket; returns None for non-IP traffic."""
    if not SCAPY_AVAILABLE:
        return None
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    protocol = "Other"
    src_port = 0
    dst_port = 0

    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    return RawPacket(
        timestamp=float(pkt.time),
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=int(ip.len),
    )


def capture_live(
    interface: str,
    duration: int = 60,
    packet_count: int = 0,
    on_packet: Callable[[RawPacket], None] | None = None,
) -> list[RawPacket]:
    """
    Capture packets from a live interface for `duration` seconds.

    Args:
        interface: Network interface name (e.g. 'eth0', 'lo').
        duration:  How long to sniff in seconds.
        packet_count: Stop after this many packets (0 = unlimited).
        on_packet: Optional callback invoked for each captured packet.

    Returns:
        List of RawPacket objects.

    Raises:
        RuntimeError: If scapy is not installed or capture fails.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "scapy is not installed. Install with: pip install scapy"
        )

    packets: list[RawPacket] = []

    def _handler(pkt):
        raw = _extract_packet(pkt)
        if raw is not None:
            packets.append(raw)
            if on_packet:
                on_packet(raw)

    sniff(
        iface=interface,
        prn=_handler,
        timeout=duration,
        count=packet_count or 0,
        store=False,
    )
    return packets


def capture_pcap(path: str | Path) -> list[RawPacket]:
    """
    Read packets from a PCAP file.

    Args:
        path: Path to .pcap or .pcapng file.

    Returns:
        List of RawPacket objects (non-IP packets excluded).

    Raises:
        RuntimeError: If scapy is not installed.
        FileNotFoundError: If the PCAP file does not exist.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "scapy is not installed. Install with: pip install scapy"
        )

    pcap_path = Path(path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    pkts = rdpcap(str(pcap_path))
    result: list[RawPacket] = []
    for pkt in pkts:
        raw = _extract_packet(pkt)
        if raw is not None:
            result.append(raw)
    return result


def synthetic_packets(
    n: int = 500,
    base_time: float | None = None,
    duration: float = 60.0,
    seed: int = 42,
) -> list[RawPacket]:
    """
    Generate synthetic packets for demo/testing without root or live traffic.

    Produces realistic-looking traffic: a mix of web (80/443), DNS (53),
    SSH (22), and random internal traffic.

    Args:
        n:         Number of packets to generate.
        base_time: Start timestamp (default: current time).
        duration:  Time span to spread packets across.
        seed:      Random seed for reproducibility.

    Returns:
        List of RawPacket objects.
    """
    import random
    rng = random.Random(seed)
    base = base_time or time.time()

    internal_ips = [f"10.0.0.{i}" for i in range(1, 20)]
    external_ips = [f"8.8.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(10)]

    common_dst_ports = [80, 443, 53, 22, 8080, 3389, 445, 25, 587, 993]
    protocols = ["TCP"] * 6 + ["UDP"] * 3 + ["ICMP"] * 1

    packets: list[RawPacket] = []
    for _ in range(n):
        proto = rng.choice(protocols)
        src = rng.choice(internal_ips)
        dst = rng.choice(internal_ips + external_ips)
        if dst == src:
            dst = rng.choice(external_ips)

        dst_port = rng.choice(common_dst_ports) if proto != "ICMP" else 0
        src_port = rng.randint(1024, 65535) if proto != "ICMP" else 0
        length = rng.randint(64, 1500)
        ts = base + rng.uniform(0, duration)

        packets.append(RawPacket(
            timestamp=ts,
            src_ip=src,
            dst_ip=dst,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
        ))

    packets.sort(key=lambda p: p.timestamp)
    return packets
