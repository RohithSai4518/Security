"""
Unit tests for Web Security Auditor and Mock Sandbox Target.
"""

import unittest
from secsuite.web.mock_target import SandboxServer
from secsuite.web.headers_auditor import HeadersAuditor
from secsuite.web.url_fuzzer import URLFuzzer

class TestWebModule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sandbox_port = 8899
        cls.server = SandboxServer(host="127.0.0.1", port=cls.sandbox_port)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_headers_auditor_against_sandbox(self):
        auditor = HeadersAuditor()
        result = auditor.audit(f"http://127.0.0.1:{self.sandbox_port}/")
        self.assertEqual(result.status_code, 200)
        self.assertGreater(len(result.missing_security_headers), 0)
        # Check info leaks detected
        leak_names = [leak["header"] for leak in result.information_leaks]
        self.assertTrue("Server" in leak_names or "X-Powered-By" in leak_names)

    def test_url_fuzzer_against_sandbox(self):
        fuzzer = URLFuzzer(base_url=f"http://127.0.0.1:{self.sandbox_port}", timeout=1.0)
        wordlist = ["robots.txt", "admin", ".env", "nonexistent_file_xyz"]
        results = fuzzer.scan(wordlist=wordlist)
        
        found_paths = {r.path: r.status_code for r in results}
        self.assertIn("robots.txt", found_paths)
        self.assertEqual(found_paths["robots.txt"], 200)
        self.assertIn("admin", found_paths)
        self.assertEqual(found_paths["admin"], 401)
        self.assertIn(".env", found_paths)
        self.assertEqual(found_paths[".env"], 200)

if __name__ == "__main__":
    unittest.main()
