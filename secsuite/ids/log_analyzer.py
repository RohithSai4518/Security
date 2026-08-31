"""
Multi-format Log Parser and Intrusion Detection System (IDS).
Detects Brute Force Attacks, Web Exploits, and anomalous access spikes.
"""

import os
import re
import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict

from secsuite.core.logger import logger
from secsuite.ids.signature_engine import SignatureEngine
from secsuite.ids.alert_manager import AlertManager, Alert

# Regex for Common Log Format (Nginx/Apache)
# e.g.: 192.0.2.45 - - [31/Aug/2026:21:40:02 +0000] "GET /admin.php HTTP/1.1" 404 123 "referer" "user-agent"
CLF_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>[^\s]+)\s+[^"]+"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)

# Regex for Linux Syslog / Auth.log
# e.g.: Aug 31 21:40:02 debian sshd[12345]: Failed password for root from 192.0.2.100 port 54321 ssh2
SYSLOG_AUTH_PATTERN = re.compile(
    r'(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[^:]+):\s+(?P<message>.*)'
)

IP_EXTRACTOR = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

class LogAnalyzer:
    """Parses and analyzes server access & system logs to detect malicious activities."""

    def __init__(self, brute_force_threshold: int = 5, alert_db: str = ":memory:"):
        self.signature_engine = SignatureEngine()
        self.alert_manager = AlertManager(db_path=alert_db)
        self.brute_force_threshold = brute_force_threshold
        self.failed_login_tracker = defaultdict(list)

    def _extract_ip(self, text: str) -> str:
        match = IP_EXTRACTOR.search(text)
        return match.group(0) if match else "UNKNOWN"

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        logger.info(f"Analyzing log file: {filepath}")
        lines_processed = 0
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                lines_processed += 1
                source_ip = self._extract_ip(line_str)

                # Check against signature rules
                matched_sigs = self.signature_engine.evaluate_line(line_str)
                for sig in matched_sigs:
                    alert = Alert(
                        timestamp=now_str,
                        source_ip=source_ip,
                        severity=sig.severity,
                        category=sig.category,
                        rule_id=sig.sig_id,
                        summary=sig.name,
                        raw_event=line_str[:250]
                    )
                    self.alert_manager.add_alert(alert)
                    logger.warning(f"IDS ALERT [{sig.severity}] ({sig.sig_id}) from {source_ip}: {sig.name}")

                # Check for Brute Force (Auth log patterns)
                if "Failed password" in line_str or "authentication failure" in line_str:
                    self.failed_login_tracker[source_ip].append(line_str)
                    if len(self.failed_login_tracker[source_ip]) == self.brute_force_threshold:
                        bf_alert = Alert(
                            timestamp=now_str,
                            source_ip=source_ip,
                            severity="CRITICAL",
                            category="Brute Force",
                            rule_id="RULE-BF-001",
                            summary=f"Brute Force Attack Detected ({self.brute_force_threshold} failed attempts threshold reached)",
                            raw_event=line_str[:250]
                        )
                        self.alert_manager.add_alert(bf_alert)
                        logger.critical(f"BRUTE FORCE DETECTED: {source_ip} exceeded {self.brute_force_threshold} failed logins!")

        summary = self.alert_manager.get_severity_summary()
        top_attackers = self.alert_manager.get_top_attackers()
        all_alerts = self.alert_manager.get_all_alerts()

        logger.info(f"Analysis complete on {lines_processed} lines. Total alerts generated: {len(all_alerts)}")

        return {
            "file": filepath,
            "lines_processed": lines_processed,
            "alert_count": len(all_alerts),
            "severity_summary": summary,
            "top_attackers": top_attackers,
            "alerts": all_alerts
        }
