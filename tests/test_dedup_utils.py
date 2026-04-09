import unittest
from types import SimpleNamespace


class TestDedupUtils(unittest.TestCase):
    def test_sha256_fingerprint_prefers_cert_attr(self):
        from src.scanner.dedup_utils import compute_dedup_values
        cert = SimpleNamespace(fingerprint_sha256="ABCDEF123456")
        algo, value, h = compute_dedup_values(1, cert)
        self.assertEqual(algo, "sha256")
        self.assertEqual(value, "ABCDEF123456")
        self.assertEqual(len(h), 64)

    def test_public_key_fp_fallback(self):
        from src.scanner.dedup_utils import compute_dedup_values
        details = {"subject_public_key_info": {"public_key_fingerprint_sha256": "PK123"}}
        cert = SimpleNamespace(fingerprint_sha256=None, certificate_details=details)
        algo, value, h = compute_dedup_values(10, cert)
        self.assertEqual(algo, "sha256")
        self.assertEqual(value, "PK123")
        self.assertEqual(len(h), 64)

    def test_sha1_and_md5_fallbacks(self):
        from src.scanner.dedup_utils import compute_dedup_values
        cert1 = SimpleNamespace(fingerprint_sha256=None, certificate_details={"fingerprint_sha1": "F1"})
        algo1, value1, h1 = compute_dedup_values(2, cert1)
        self.assertEqual(algo1, "sha1")
        self.assertTrue(value1.startswith("sha1:"))

        cert2 = SimpleNamespace(fingerprint_sha256=None, certificate_details={"fingerprint_md5": "FM"})
        algo2, value2, h2 = compute_dedup_values(3, cert2)
        self.assertEqual(algo2, "md5")
        self.assertTrue(value2.startswith("md5:"))


if __name__ == '__main__':
    unittest.main()
