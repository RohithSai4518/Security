"""
Built-in lightweight sandbox HTTP server for safe offline vulnerability and security testing.
Runs on localhost with zero external dependencies.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json
import time
from typing import Optional

class SandboxHTTPHandler(BaseHTTPRequestHandler):
    """Handles mock requests to simulate various security configurations and endpoints."""

    def log_message(self, format, *args):
        # Suppress default noisy console logs
        pass

    def do_GET(self):
        # Simulated endpoints
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache-Coyote/1.1 (Simulated-Leak)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            # Missing critical security headers intentionally to test auditor
            self.end_headers()
            self.wfile.write(b"<html><body><h1>PySecSuite Sandbox Mock Target</h1><p>Running safely on localhost.</p></body></html>")
        
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /api/v1/private\n")

        elif self.path == "/admin":
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"401 Unauthorized: Admin portal requires credentials.")

        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"# DUMMY SYNTHETIC TESTING CONFIG ONLY\nAPP_ENV=sandbox_test\nDB_HOST=127.0.0.1\n")

        elif self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "uptime": 120}).encode("utf-8"))

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")

class SandboxServer:
    """Controls background lifecycle of the local testing sandbox server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8888):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self.server = HTTPServer((self.host, self.port), SandboxHTTPHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        # Give server time to bind
        time.sleep(0.2)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
