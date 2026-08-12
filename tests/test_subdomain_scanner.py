import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import asyncio

from src.scanner.subdomain_scanner import SubfinderScanner, execute_subdomain_scan
from src.services.subdomain_service import SubdomainService


class TestSubfinderScanner(unittest.TestCase):
    def test_binary_resolution_local_or_system(self):
        scanner = SubfinderScanner()
        self.assertIsNotNone(scanner.binary_path)
        self.assertTrue(Path(scanner.binary_path).name.startswith("subfinder"))

    @patch("subprocess.run")
    def test_run_passive_enumeration_success(self, mock_run):
        mock_process = MagicMock()
        mock_process.stdout = '{"host":"sub1.example.com","ip":"1.1.1.1"}\n{"host":"sub2.example.com","ip":"2.2.2.2"}\n'
        mock_run.return_value = mock_process

        scanner = SubfinderScanner()
        results = scanner.run_passive_enumeration("example.com")

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["host"], "sub1.example.com")
        self.assertEqual(results[1]["host"], "sub2.example.com")

    @patch("src.scanner.subdomain_scanner.SubfinderScanner.run_passive_enumeration")
    @patch("src.scanner.subdomain_scanner.SubfinderScanner.verify_active_subdomains")
    def test_execute_subdomain_scan(self, mock_verify, mock_passive):
        mock_passive.return_value = [
            {"host": "sub1.example.com"},
            {"host": "sub2.example.com"}
        ]
        mock_verify.return_value = (
            {"sub1.example.com": "1.1.1.1"},
            ["sub2.example.com"]
        )

        res = execute_subdomain_scan("example.com")
        self.assertEqual(res["target"], "example.com")
        self.assertEqual(res["total_passive_found"], 2)
        self.assertEqual(res["total_live_found"], 1)
        self.assertEqual(res["total_unresolved_found"], 1)

    @patch("src.scanner.subdomain_scanner.execute_subdomain_scan")
    def test_subdomain_service_run_domain_discovery(self, mock_scan):
        mock_scan.return_value = {
            "target": "example.com",
            "total_passive_found": 1,
            "total_live_found": 1,
            "total_unresolved_found": 0,
            "live_subdomains": {"sub.example.com": "1.2.3.4"},
            "unresolved_subdomains": [],
            "sources": [{"host": "sub.example.com"}]
        }

        res = SubdomainService.run_domain_discovery("example.com")
        self.assertEqual(res["target"], "example.com")
        self.assertIn("live_subdomains", res)


if __name__ == "__main__":
    unittest.main()
