"""
HTTP Security Headers Auditor and Hardening Evaluator.
Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
"""

import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

from secsuite.core.logger import logger
from secsuite.core.config import GLOBAL_CONFIG

SECURITY_HEADERS_POLICY = {
    "Strict-Transport-Security": {
        "importance": "CRITICAL",
        "description": "Enforces HTTPS connections and prevents SSL-stripping attacks.",
        "recommended": "max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "importance": "CRITICAL",
        "description": "Restricts sources of executable scripts, stylesheets, and assets to mitigate XSS.",
        "recommended": "default-src 'self'; script-src 'self'"
    },
    "X-Frame-Options": {
        "importance": "HIGH",
        "description": "Prevents Clickjacking by disallowing framing in iframes.",
        "recommended": "DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "importance": "HIGH",
        "description": "Stops MIME-sniffing away from the declared content-type.",
        "recommended": "nosniff"
    },
    "Referrer-Policy": {
        "importance": "MEDIUM",
        "description": "Controls how much referrer information is sent with requests.",
        "recommended": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "importance": "MEDIUM",
        "description": "Restricts browser features such as camera, microphone, geolocation.",
        "recommended": "geolocation=(), camera=(), microphone=()"
    }
}

LEAKING_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]

@dataclass
class HeaderAuditResult:
    url: str
    status_code: int
    score_percentage: float
    grade: str
    present_headers: Dict[str, str]
    missing_security_headers: List[Dict[str, str]]
    information_leaks: List[Dict[str, str]]

class HeadersAuditor:
    """Performs HTTP Security Header analysis."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def audit(self, url: str) -> HeaderAuditResult:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"https://{url}"

        logger.info(f"Auditing HTTP Security Headers for: {url}")

        req = urllib.request.Request(
            url,
            headers={"User-Agent": GLOBAL_CONFIG.user_agent}
        )

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                status_code = response.getcode()
                raw_headers = dict(response.info())
        except urllib.error.HTTPError as e:
            status_code = e.code
            raw_headers = dict(e.headers)
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            raise

        # Case-insensitive headers map
        headers_lower = {k.lower(): (k, v) for k, v in raw_headers.items()}

        present_headers = {}
        missing_headers = []
        info_leaks = []

        total_weight = 0
        earned_weight = 0

        weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}

        for sec_header, spec in SECURITY_HEADERS_POLICY.items():
            w = weights.get(spec["importance"], 10)
            total_weight += w
            sec_lower = sec_header.lower()

            if sec_lower in headers_lower:
                actual_name, val = headers_lower[sec_lower]
                present_headers[actual_name] = val
                earned_weight += w
                logger.success(f"[PASS] {actual_name}: {val[:60]}")
            else:
                missing_headers.append({
                    "header": sec_header,
                    "importance": spec["importance"],
                    "description": spec["description"],
                    "recommended": spec["recommended"]
                })
                logger.warning(f"[MISSING] [{spec['importance']}] {sec_header}")

        # Check info leaks
        for leak in LEAKING_HEADERS:
            if leak.lower() in headers_lower:
                actual_name, val = headers_lower[leak.lower()]
                info_leaks.append({"header": actual_name, "value": val})
                logger.warning(f"[INFO LEAK] {actual_name}: {val}")

        score = round((earned_weight / total_weight) * 100, 1)
        if score >= 90:
            grade = "A+"
        elif score >= 75:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 30:
            grade = "D"
        else:
            grade = "F"

        logger.info(f"Audit completed. Security Score: {score}% (Grade: {grade})")

        return HeaderAuditResult(
            url=url,
            status_code=status_code,
            score_percentage=score,
            grade=grade,
            present_headers=present_headers,
            missing_security_headers=missing_headers,
            information_leaks=info_leaks
        )
