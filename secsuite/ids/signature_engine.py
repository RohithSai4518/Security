"""
Attack Signatures and Behavioral Rule Engine for Log-based Intrusion Detection.
"""

import re
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class AttackSignature:
    sig_id: str
    name: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    pattern: re.Pattern
    description: str

BUILTIN_SIGNATURES: List[AttackSignature] = [
    AttackSignature(
        sig_id="SIG-SQLI-001",
        name="SQL Injection: UNION SELECT / OR 1=1 Attack",
        category="Web Attack",
        severity="HIGH",
        pattern=re.compile(r"(\bunion\b[\s+]+(?:\b[a-z0-9_]+\b[\s+,]*)*\bselect\b|\bor\b\s+['\d=]+|\b1=1\b|--|\bwaitfor\b\s+\bdelay\b)", re.IGNORECASE),
        description="Detected classic SQL injection pattern in query string or path."
    ),
    AttackSignature(
        sig_id="SIG-TRAV-001",
        name="Directory Path Traversal",
        category="File System Attack",
        severity="HIGH",
        pattern=re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|\betc/passwd\b|\bwindows/win\.ini\b|\bboot\.ini\b)", re.IGNORECASE),
        description="Detected attempts to traverse out of the web root directory."
    ),
    AttackSignature(
        sig_id="SIG-XSS-001",
        name="Cross-Site Scripting (XSS) Payload",
        category="Web Attack",
        severity="MEDIUM",
        pattern=re.compile(r"(<script\b[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie)", re.IGNORECASE),
        description="Detected script injection or event handler XSS string."
    ),
    AttackSignature(
        sig_id="SIG-RCE-001",
        name="Command Injection / Remote Code Execution",
        category="Code Execution",
        severity="CRITICAL",
        pattern=re.compile(r"(;\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh|powershell|cmd)\b|\b(?:system|exec|passthru|shell_exec)\s*\(|`[^`]+`)", re.IGNORECASE),
        description="Detected shell command chaining or execution indicators."
    ),
    AttackSignature(
        sig_id="SIG-SCAN-001",
        name="Vulnerability Scanner User Agent / Probing",
        category="Reconnaissance",
        severity="LOW",
        pattern=re.compile(r"(sqlmap|nikto|nmap|acunetix|dirbuster|gobuster|wpscan|masscan|zgrab)", re.IGNORECASE),
        description="Recognized automated vulnerability scanner or directory brute-forcer signature."
    ),
    AttackSignature(
        sig_id="SIG-SENS-001",
        name="Sensitive File Access Attempt",
        category="Information Disclosure",
        severity="MEDIUM",
        pattern=re.compile(r"(\.env|\.git/config|id_rsa|\.aws/credentials|wp-config\.php|backup\.sql|\.htpasswd)", re.IGNORECASE),
        description="Targeting sensitive environment configs, credentials, or repository trees."
    ),
    AttackSignature(
        sig_id="SIG-AUTH-001",
        name="SSH / Auth Failed Login Indicator",
        category="Authentication",
        severity="LOW",
        pattern=re.compile(r"(Failed password for|authentication failure|Invalid user|Failed publickey)", re.IGNORECASE),
        description="System authentication failure event."
    )
]

class SignatureEngine:
    """Evaluates text streams and log lines against attack signatures."""

    def __init__(self, custom_signatures: Optional[List[AttackSignature]] = None):
        self.signatures = BUILTIN_SIGNATURES + (custom_signatures or [])

    def evaluate_line(self, line: str) -> List[AttackSignature]:
        decoded_line = urllib.parse.unquote_plus(line)
        matched = []
        for sig in self.signatures:
            if sig.pattern.search(line) or sig.pattern.search(decoded_line):
                matched.append(sig)
        return matched

