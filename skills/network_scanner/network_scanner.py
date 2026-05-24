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
    for probe_port in [80, 443, 22, 445]:
        _, is_open, _ = scan_port(ip, probe_port, timeout)
        if is_open:
            return True
    return False


def scan_host(host: str, ports: List[int], max_workers: int = 100) -> Dict:
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
            port, is_open, service = future.result()
            if is_open:
                open_ports.append({"port": port, "service": service})
                logger.info(f"  [OPEN] {host}:{port} ({service})")

    elapsed = (datetime.now() - start_time).total_seconds()
    open_ports.sort(key=lambda x: x["port"])

    return {
        "host": host,
        "open_ports": open_ports,
        "total_scanned": len(ports),
        "scan_duration_seconds": round(elapsed, 2),
        "timestamp": start_time.isoformat(),
    }


def parse_port_range(port_range: str) -> List[int]:
    """
    Parse a port range string like '1-1024' or '80,443,8080' into a list.

    Args:
        port_range: Port range string

    Returns:
        List of port numbers
    """
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(
        description="Basic network scanner for cybersecurity education"
    )
    parser.add_argument("--target", required=True, help="Target IP, hostname, or CIDR range")
    parser.add_argument(
        "--ports",
        default="common",
        help="Ports to scan: 'common', a range like '1-1024', or list '80,443,8080'",
    )
    parser.add_argument("--workers", type=int, default=100, help="Max concurrent threads")
    args = parser.parse_args()

    if args.ports == "common":
        ports = list(COMMON_PORTS.keys())
    else:
        ports = parse_port_range(args.ports)

    logger.info(f"Starting scan of {args.target} on {len(ports)} ports")
    logger.info("=" * 60)

    try:
        network = ipaddress.ip_network(args.target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
    except ValueError:
        hosts = [args.target]

    results = []
    for host in hosts:
        logger.info(f"Scanning host: {host}")
        result = scan_host(host, ports, max_workers=args.workers)
        results.append(result)
        logger.info(
            f"  Found {len(result['open_ports'])} open ports in {result['scan_duration_seconds']}s"
        )

    logger.info("=" * 60)
    logger.info(f"Scan complete. {len(results)} host(s) scanned.")
    return results


if __name__ == "__main__":
    main()
