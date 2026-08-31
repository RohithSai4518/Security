"""
Unit tests for Signature Engine and Log-based IDS module.
"""

import unittest
import os
import tempfile
from secsuite.ids.signature_engine import SignatureEngine
from secsuite.ids.log_analyzer import LogAnalyzer
from secsuite.ids.alert_manager import AlertManager, Alert

class TestIDSModule(unittest.TestCase):

    def setUp(self):
        self.sig_engine = SignatureEngine()

    def test_sqli_signature_match(self):
        line = '192.0.2.1 - - [31/Aug/2026:12:00:00] "GET /products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 450'
        matches = self.sig_engine.evaluate_line(line)
        self.assertTrue(any(m.sig_id == "SIG-SQLI-001" for m in matches))

    def test_path_traversal_match(self):
        line = '192.0.2.5 - - [31/Aug/2026:12:01:00] "GET /view?file=../../etc/passwd HTTP/1.1" 404 120'
        matches = self.sig_engine.evaluate_line(line)
        self.assertTrue(any(m.sig_id == "SIG-TRAV-001" for m in matches))

    def test_xss_signature_match(self):
        line = '192.0.2.8 - - [31/Aug/2026:12:02:00] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 890'
        matches = self.sig_engine.evaluate_line(line)
        self.assertTrue(any(m.sig_id == "SIG-XSS-001" for m in matches))

    def test_alert_manager_storage(self):
        mgr = AlertManager(":memory:")
        alert = Alert(
            timestamp="2026-08-31T12:00:00",
            source_ip="192.0.2.55",
            severity="CRITICAL",
            category="Code Execution",
            rule_id="SIG-RCE-001",
            summary="Command Injection Detected",
            raw_event="; cat /etc/shadow"
        )
        mgr.add_alert(alert)
        alerts = mgr.get_all_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "192.0.2.55")
        
        summary = mgr.get_severity_summary()
        self.assertEqual(summary["CRITICAL"], 1)

    def test_log_analyzer_brute_force_detection(self):
        log_content = """
Aug 31 10:00:01 debian sshd[100]: Failed password for invalid user admin from 192.0.2.88 port 4001 ssh2
Aug 31 10:00:02 debian sshd[101]: Failed password for invalid user admin from 192.0.2.88 port 4002 ssh2
Aug 31 10:00:03 debian sshd[102]: Failed password for invalid user admin from 192.0.2.88 port 4003 ssh2
192.0.2.99 - - [31/Aug/2026:10:00:05] "GET /admin/config.json HTTP/1.1" 200 450
"""
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as f:
            f.write(log_content)
            temp_path = f.name

        try:
            analyzer = LogAnalyzer(brute_force_threshold=3)
            result = analyzer.analyze_file(temp_path)
            self.assertGreaterEqual(result["alert_count"], 3)
            self.assertTrue(any(a["category"] == "Brute Force" for a in result["alerts"]))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

if __name__ == "__main__":
    unittest.main()
