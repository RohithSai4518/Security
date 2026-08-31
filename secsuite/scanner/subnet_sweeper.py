"""
Subnet IP Discovery and Live Host Sweeper.
"""

import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List

from secsuite.core.logger import logger

@dataclass
class HostStatus:
    ip: str
    is_alive: bool
    open_probe_port: int = 0
    latency_ms: float = 0.0

@dataclass
class SubnetReport:
    cidr: str
    total_hosts_tested: int
    alive_hosts: List[HostStatus] = field(default_factory=list)
    duration_seconds: float = 0.0

class SubnetSweeper:
    """Discovers responsive hosts within an IPv4 CIDR range using TCP probe sweeps."""

    def __init__(self, cidr: str, probe_ports: List[int] = None, timeout: float = 0.8, max_threads: int = 40):
        self.cidr = cidr
        self.probe_ports = probe_ports or [80, 443, 22, 445, 135, 8080]
        self.timeout = timeout
        self.max_threads = max_threads

    def _probe_host(self, ip_str: str) -> HostStatus:
        start_time = time.perf_counter()
        
        for port in self.probe_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((ip_str, port)) == 0:
                        latency = (time.perf_counter() - start_time) * 1000.0
                        return HostStatus(ip=ip_str, is_alive=True, open_probe_port=port, latency_ms=round(latency, 2))
            except socket.error:
                continue

        return HostStatus(ip=ip_str, is_alive=False)

    def sweep(self, max_hosts: int = 256) -> SubnetReport:
        try:
            network = ipaddress.ip_network(self.cidr, strict=False)
        except ValueError as e:
            logger.error(f"Invalid CIDR notation '{self.cidr}': {e}")
            raise

        hosts = [str(ip) for ip in network.hosts()][:max_hosts]
        logger.info(f"Starting host discovery sweep across {len(hosts)} hosts in subnet {self.cidr}...")

        start_time = time.perf_counter()
        alive_hosts: List[HostStatus] = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {executor.submit(self._probe_host, ip): ip for ip in hosts}
            for future in as_completed(future_to_ip):
                status = future.result()
                if status.is_alive:
                    logger.success(f"Host ACTIVE: {status.ip:<16} (Port {status.open_probe_port} responded in {status.latency_ms}ms)")
                    alive_hosts.append(status)

        duration = round(time.perf_counter() - start_time, 2)
        alive_hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))

        logger.info(f"Subnet sweep completed in {duration}s. Found {len(alive_hosts)} active hosts.")
        return SubnetReport(
            cidr=self.cidr,
            total_hosts_tested=len(hosts),
            alive_hosts=alive_hosts,
            duration_seconds=duration
        )
