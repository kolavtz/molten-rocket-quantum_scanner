"""
Unit tests for CBOM Builder and CycloneDX Generator.
"""
import json
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.cbom.builder import CBOMBuilder, CryptoAsset, CBOM
from src.cbom.cyclonedx_generator import CycloneDXGenerator


# ── Fixtures ──

SAMPLE_TLS_RESULTS = [
    {
        "host": "bank-api.example.com",
        "port": 443,
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "key_exchange": "TLS1.3-ECDHE",
        "certificate": {
            "subject": {"commonName": "bank-api.example.com"},
            "issuer": {"commonName": "DigiCert"},
            "serial_number": "ABC123",
            "not_before": "Jan  1 00:00:00 2024 GMT",
            "not_after": "Dec 31 23:59:59 2025 GMT",
            "signature_algorithm": "sha256WithRSAEncryption",
            "public_key_type": "RSA",
            "public_key_bits": 2048,
            "fingerprint_sha256": "AABBCCDD" * 8,
            "is_expired": False,
            "days_until_expiry": 300,
        },
        "certificate_chain_length": 3,
        "supported_protocols": ["TLSv1.2", "TLSv1.3"],
        "all_cipher_suites": [],
    },
]

SAMPLE_PQC_ASSESSMENTS = [
    {
        "host": "bank-api.example.com",
        "port": 443,
        "is_quantum_safe": False,
        "overall_status": "quantum_vulnerable",
        "risk_level": "HIGH",
        "quantum_safe_algorithms": [],
        "quantum_vulnerable_algorithms": [
            {"name": "ECDHE", "status": "quantum_vulnerable"},
        ],
    },
]


class TestCryptoAsset:
    """Tests for CryptoAsset dataclass."""

    def test_auto_id(self):
        asset = CryptoAsset(host="test.com", port=443)
        assert asset.asset_id != ""

    def test_to_dict(self):
        asset = CryptoAsset(host="test.com", port=443, cipher_suite="AES256")
        d = asset.to_dict()
        assert d["host"] == "test.com"
        assert d["cipher_suite"] == "AES256"


class TestCBOM:
    """Tests for CBOM container."""

    def test_auto_serial(self):
        cbom = CBOM()
        assert cbom.serial_number.startswith("urn:uuid:")

    def test_counts(self):
        cbom = CBOM()
        cbom.assets = [
            CryptoAsset(host="a.com", port=443, is_quantum_safe=True),
            CryptoAsset(host="b.com", port=443, is_quantum_safe=False),
            CryptoAsset(host="c.com", port=443, is_quantum_safe=False),
        ]
        assert cbom.total_assets == 3
        assert cbom.quantum_safe_count == 1
        assert cbom.quantum_vulnerable_count == 2


class TestCBOMBuilder:
    """Tests for CBOMBuilder.build()."""

    def test_build_creates_cbom(self):
        builder = CBOMBuilder()
        cbom = builder.build(SAMPLE_TLS_RESULTS, SAMPLE_PQC_ASSESSMENTS)
        assert cbom.total_assets == 1
        assert cbom.assets[0].host == "bank-api.example.com"
        assert cbom.assets[0].cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert cbom.assets[0].is_quantum_safe is False

    def test_to_dict_structure(self):
        builder = CBOMBuilder()
        cbom = builder.build(SAMPLE_TLS_RESULTS, SAMPLE_PQC_ASSESSMENTS)
        d = cbom.to_dict()
        assert "serial_number" in d
        assert "summary" in d
        assert d["summary"]["total_assets"] == 1


class TestCycloneDXGenerator:
    """Tests for CycloneDXGenerator."""

    def test_manual_generation(self):
        builder = CBOMBuilder()
        cbom = builder.build(SAMPLE_TLS_RESULTS, SAMPLE_PQC_ASSESSMENTS)
        gen = CycloneDXGenerator()
        json_str = gen._generate_manual(cbom.to_dict())
        doc = json.loads(json_str)
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        # 1 host asset + 6 CERT-IN cryptographic assets (algorithms, protocols, certs)
        assert len(doc["components"]) == 7

    def test_component_properties(self):
        builder = CBOMBuilder()
        cbom = builder.build(SAMPLE_TLS_RESULTS, SAMPLE_PQC_ASSESSMENTS)
        gen = CycloneDXGenerator()
        json_str = gen._generate_manual(cbom.to_dict())
        doc = json.loads(json_str)
        comp = doc["components"][0]
        prop_names = [p["name"] for p in comp["properties"]]
        assert "quantum-safe:cipher_suite" in prop_names
        assert "quantum-safe:pqc_status" in prop_names

    def test_export_json(self, tmp_path):
        builder = CBOMBuilder()
        cbom = builder.build(SAMPLE_TLS_RESULTS, SAMPLE_PQC_ASSESSMENTS)
        gen = CycloneDXGenerator()
        path = str(tmp_path / "cbom.json")
        gen.export_json(cbom.to_dict(), path)
        assert os.path.exists(path)
        with open(path, "r") as fh:
            data = json.load(fh)
        assert data["bomFormat"] == "CycloneDX"
