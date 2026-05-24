#!/usr/bin/env python3
"""
Network Scanner Skill for Anthropic Cybersecurity Skills

This skill provides basic network scanning capabilities including
host discovery, port scanning, and service detection.

Usage:
    python network_scanner.py --target 192.168.1.0/24
    python network_scanner.py --target 192.168.1.1 --ports 1-1024

WARNING: Only use on networks you own or have explicit permission to scan.
"""

import socket
import ipaddress
import argparse
import concurrent.futures
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Common ports and their typical services
COMMON_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
    9200: "Elasticsearch",  # added - commonly exposed in home lab setups
    5900: "VNC",            # added - useful to detect remote desktop exposure
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """
    Attempt to connect to a specific port on a host.

    Args:
        host: Target IP address or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (port, is_open, service_name)
    """
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            is_open = result == 0
            return (port, is_open, service)
    except (socket.error, OSError):
        return (port, False, service)


def discover_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Check if a host is reachable by attempting connection on port 80 or ICMP-like probe.

    Args:
        ip: IP address to probe
        timeout: Connection timeout in seconds

    Returns:
        True if host appears to be up
    """
    # Added port 8080 to probe list since many dev/home lab services run there
    for probe_port in [80, 443, 22, 445, 8080]:
        _, is_open, _ = scan_port(ip, probe_port, timeout)
        if is_open:
            return True
    return False


def scan_host(host: str, ports: List[int], max_workers: int = 50) -> Dict:
    """
    Scan a single host for open ports.

    Args:
        host: Target IP address or hostname
        ports: List of port numbers to scan
        max_workers: Maximum concurrent threads

    Returns:
        Dictionary containing scan results
    """
    open_ports = []
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
