"""
Multi-threaded TCP Connect Port Scanner and Service Banner Grabber.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import time

from secsuite.core.logger import logger
from secsuite.core.config import GLOBAL_CONFIG

WELL_KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

@dataclass
class PortResult:
    port: int
    is_open: bool
    service: str = "Unknown"
    banner: str = ""
    latency_ms: float = 0.0

@dataclass
class ScanReport:
    target_host: str
    target_ip: str
    total_ports_scanned: int
    open_ports: List[PortResult] = field(default_factory=list)
    duration_seconds: float = 0.0

class PortScanner:
    """High-performance multi-threaded TCP Port Scanner and Banner Grabber."""

    def __init__(self, target: str, timeout: float = 1.0, max_threads: int = 50):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads

    def _resolve_host(self) -> Tuple[str, str]:
        try:
            ip = socket.gethostbyname(self.target)
            return self.target, ip
        except socket.gaierror as e:
            logger.error(f"Failed to resolve host '{self.target}': {e}")
            raise

    def _grab_banner(self, ip: str, port: int) -> str:
        """Attempts to retrieve a service banner upon connection."""
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(GLOBAL_CONFIG.banner_grab_timeout)
                s.connect((ip, port))
                
                # For HTTP/HTTPS ports, send a light HEAD request
                if port in (80, 8080, 8000):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                elif port in (21, 22, 25, 110, 143):
                    pass  # Services usually send banner immediately upon connect
                else:
                    s.sendall(b"\r\n")

                data = s.recv(1024)
                if data:
                    # Clean up banner
                    banner = data.decode("utf-8", errors="ignore").strip().split("\n")[0][:120]
        except (socket.timeout, socket.error, ConnectionResetError):
            pass
        return banner

    def _scan_single_port(self, ip: str, port: int) -> PortResult:
        start_time = time.perf_counter()
        is_open = False
        banner = ""
        service = WELL_KNOWN_SERVICES.get(port, "Unknown")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    is_open = True
        except socket.error:
            pass

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if is_open:
            banner = self._grab_banner(ip, port)

        return PortResult(
            port=port,
            is_open=is_open,
            service=service,
            banner=banner,
            latency_ms=round(latency_ms, 2)
        )

    def scan(self, ports: Optional[List[int]] = None) -> ScanReport:
        target_host, target_ip = self._resolve_host()
        target_ports = ports or GLOBAL_CONFIG.default_ports

        logger.info(f"Starting port scan against {target_host} ({target_ip}) on {len(target_ports)} ports...")
        start_time = time.perf_counter()

        open_results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(target_ports) or 1)) as executor:
            future_to_port = {
                executor.submit(self._scan_single_port, target_ip, p): p for p in target_ports
            }

            for future in as_completed(future_to_port):
                port_res = future.result()
                if port_res.is_open:
                    logger.success(f"Port {port_res.port:<5} OPEN | Service: {port_res.service:<12} | Banner: {port_res.banner or 'N/A'}")
                    open_results.append(port_res)

        # Sort by port number
        open_results.sort(key=lambda r: r.port)
        duration = round(time.perf_counter() - start_time, 3)

        logger.info(f"Scan complete for {target_host} in {duration}s. Found {len(open_results)} open ports.")
        
        return ScanReport(
            target_host=target_host,
            target_ip=target_ip,
            total_ports_scanned=len(target_ports),
            open_ports=open_results,
            duration_seconds=duration
        )
