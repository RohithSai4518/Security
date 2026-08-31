"""
Fast, non-destructive endpoint & sensitive file discovery.
"""

import urllib.request
import urllib.error
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional

from secsuite.core.logger import logger
from secsuite.core.config import GLOBAL_CONFIG

DEFAULT_DISCOVERY_WORDLIST = [
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".git/config",
    ".gitignore",
    "admin",
    "admin.php",
    "login",
    "dashboard",
    "api",
    "api/v1",
    "api/v2",
    "swagger.json",
    "openapi.json",
    "backup.zip",
    "backup.sql",
    "config.json",
    "server-status",
    ".well-known/security.txt",
    "health",
    "metrics",
]

@dataclass
class FuzzResult:
    path: str
    status_code: int
    content_length: int
    redirect_url: str = ""

class URLFuzzer:
    """Discovers accessible endpoints and exposed sensitive resources."""

    def __init__(self, base_url: str, timeout: float = 2.0, max_threads: int = 10):
        self.base_url = base_url.rstrip("/")
        if not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            self.base_url = f"http://{self.base_url}"
        self.timeout = timeout
        self.max_threads = max_threads

    def _probe_path(self, path: str) -> Optional[FuzzResult]:
        target_url = f"{self.base_url}/{path.lstrip('/')}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": GLOBAL_CONFIG.user_agent}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                status = response.getcode()
                length = len(response.read())
                redirect = response.geturl() if response.geturl() != target_url else ""
                return FuzzResult(path=path, status_code=status, content_length=length, redirect_url=redirect)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 500):
                return FuzzResult(path=path, status_code=e.code, content_length=0)
            return None
        except Exception:
            return None

    def scan(self, wordlist: Optional[List[str]] = None) -> List[FuzzResult]:
        paths = wordlist or DEFAULT_DISCOVERY_WORDLIST
        logger.info(f"Starting sensitive path discovery on {self.base_url} ({len(paths)} paths)...")

        discovered: List[FuzzResult] = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {executor.submit(self._probe_path, p): p for p in paths}
            for future in as_completed(future_to_path):
                res = future.result()
                if res:
                    if res.status_code == 200:
                        logger.success(f"[200 OK] /{res.path:<25} (Length: {res.content_length} bytes)")
                    elif res.status_code in (401, 403):
                        logger.warning(f"[{res.status_code} FORBIDDEN] /{res.path:<25}")
                    discovered.append(res)

        discovered.sort(key=lambda x: x.path)
        logger.info(f"Discovery finished. Found {len(discovered)} interesting endpoints.")
        return discovered
