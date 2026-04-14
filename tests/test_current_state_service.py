"""
Unit tests for CurrentStateService certificate normalization.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.services.current_state_service import CurrentStateService


class _DummyCert:
    def __init__(self):
        self.id = 7
        self.subject_cn = ""
        self.subject_o = ""
        self.issuer_cn = ""
        self.issuer_o = ""
        self.serial = "SER-1"
        self.fingerprint_sha256 = "ABC"
        self.valid_from = None
        self.valid_until = None
        self.expiry_days = 15
        self.is_expired = False
        self.is_self_signed = False
        self.is_current = True
        self.tls_version = "TLSv1.3"
        self.key_length = 0
        self.key_algorithm = ""
        self.public_key_type = ""
        self.cipher_suite = "TLS_AES_256_GCM_SHA384"
        self.signature_algorithm = "sha256WithRSAEncryption"
        self.ca = False
        self.san_domains = '["google.com"]'
        self.cert_chain_length = 3
        self.first_seen_at = None
        self.last_seen_at = None
        self.certificate_details = '{"subject_cn": "google.com", "issuer_cn": "Google Trust Services", "subject_public_key_info": {"subject_public_key_bits": 4096, "public_key_algorithm": "RSA"}}'


def test_cert_to_dict_backfills_flat_fields_from_certificate_details():
    data = CurrentStateService._cert_to_dict(_DummyCert())

    assert data["subject_cn"] == "google.com"
    assert data["issuer_cn"] == "Google Trust Services"
    assert data["public_key_type"] == "RSA"
    assert data["key_length"] == 4096
    assert data["san_domains"] == ["google.com"]
