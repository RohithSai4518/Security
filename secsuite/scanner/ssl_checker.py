"""
TLS/SSL Certificate Validator and Protocol Security Checker.
"""

import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from secsuite.core.logger import logger

@dataclass
class CertificateInfo:
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    version: int = 3
    serial_number: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    days_until_expiry: int = 0
    is_expired: bool = False
    san_list: List[str] = field(default_factory=list)
    tls_version: str = ""
    cipher_suite: str = ""
    is_self_signed: bool = False

class SSLChecker:
    """Evaluates TLS/SSL configuration, expiration, and certificate validity."""

    def __init__(self, host: str, port: int = 443, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _parse_x509_name(self, rdn_sequence) -> Dict[str, str]:
        parsed = {}
        for rdn in rdn_sequence:
            for attr in rdn:
                if len(attr) >= 2:
                    parsed[attr[0]] = attr[1]
        return parsed

    def check_certificate(self) -> CertificateInfo:
        logger.info(f"Inspecting SSL/TLS certificate for {self.host}:{self.port}...")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # In order to inspect self-signed certs as well

        info = CertificateInfo()

        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    info.tls_version = tls_version or "Unknown"
                    info.cipher_suite = f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)" if cipher else "Unknown"

                    if not cert:
                        # Fetch binary cert if unverified returned empty dict
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            info.serial_number = "Retrieved in raw DER format"
                        return info

                    # Subject & Issuer
                    if "subject" in cert:
                        info.subject = self._parse_x509_name(cert["subject"])
                    if "issuer" in cert:
                        info.issuer = self._parse_x509_name(cert["issuer"])

                    # Expiration parsing
                    date_format = "%b %d %H:%M:%S %Y %Z"
                    if "notBefore" in cert:
                        try:
                            info.not_before = datetime.datetime.strptime(cert["notBefore"], date_format)
                        except ValueError:
                            pass
                    if "notAfter" in cert:
                        try:
                            info.not_after = datetime.datetime.strptime(cert["notAfter"], date_format)
                            now = datetime.datetime.utcnow()
                            diff = info.not_after - now
                            info.days_until_expiry = diff.days
                            info.is_expired = diff.total_seconds() < 0
                        except ValueError:
                            pass

                    # SANs
                    if "subjectAltName" in cert:
                        info.san_list = [f"{san[0]}:{san[1]}" for san in cert["subjectAltName"]]

                    # Self-signed check
                    info.is_self_signed = (info.subject.get("commonName") == info.issuer.get("commonName")) and bool(info.subject)
                    info.version = cert.get("version", 3)
                    info.serial_number = str(cert.get("serialNumber", ""))

                    # Log findings
                    if info.is_expired:
                        logger.error(f"Certificate for {self.host} is EXPIRED ({abs(info.days_until_expiry)} days ago)!")
                    elif info.days_until_expiry < 30:
                        logger.warning(f"Certificate for {self.host} expires soon ({info.days_until_expiry} days remaining).")
                    else:
                        logger.success(f"Certificate for {self.host} valid ({info.days_until_expiry} days remaining).")

                    logger.info(f"TLS Version: {info.tls_version} | Cipher: {info.cipher_suite}")
                    return info

        except Exception as e:
            logger.error(f"TLS handshake/connection failed for {self.host}:{self.port} - {e}")
            raise
