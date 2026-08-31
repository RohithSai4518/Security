"""
Unit tests for Scanner and Subnet sweep modules.
"""

import unittest
import socket
import threading
import time
from secsuite.scanner.port_scanner import PortScanner
from secsuite.scanner.subnet_sweeper import SubnetSweeper

class TestScannerModule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Set up a mock local TCP listener on an ephemeral port
        cls.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.sock.bind(("127.0.0.1", 0))
        cls.mock_port = cls.sock.getsockname()[1]
        cls.sock.listen(5)

        cls._running = True
        def _listen_loop():
            while cls._running:
                try:
                    cls.sock.settimeout(0.5)
                    conn, _ = cls.sock.accept()
                    conn.sendall(b"SSH-2.0-MockTestBanner\r\n")
                    conn.close()
                except socket.timeout:
                    continue
                except socket.error:
                    break

        cls._thread = threading.Thread(target=_listen_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._running = False
        try:
            cls.sock.close()
        except socket.error:
            pass

    def test_port_scanner_detects_open_port(self):
        scanner = PortScanner(target="127.0.0.1", timeout=0.5, max_threads=5)
        report = scanner.scan(ports=[self.mock_port, 9999])
        self.assertEqual(report.target_ip, "127.0.0.1")
        open_ports = [p.port for p in report.open_ports]
        self.assertIn(self.mock_port, open_ports)

    def test_subnet_sweeper_validation(self):
        sweeper = SubnetSweeper(cidr="127.0.0.1/32", probe_ports=[self.mock_port], timeout=0.5)
        report = sweeper.sweep()
        self.assertEqual(report.total_hosts_tested, 1)

if __name__ == "__main__":
    unittest.main()
