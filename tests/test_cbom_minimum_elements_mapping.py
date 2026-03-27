"""Tests for Table 9 minimum element field mapping in CBOM API formatting."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from utils.api_helper import format_cbom_entry_row


def test_format_cbom_entry_row_includes_table9_minimum_fields():
    entry = SimpleNamespace(
        id=101,
        scan_id=9,
        asset_id=7,
        asset=SimpleNamespace(target="example.org"),
        algorithm_name="AES-128-GCM",
        category="cryptographic-asset",
        asset_type="algorithm",
        element_name="AES-128-GCM",
        primitive="block-cipher",
        mode="gcm",
        crypto_functions='["keygen","encrypt","decrypt"]',
        classical_security_level=128,
        oid="2.16.840.1.101.3.4.1.6",
        element_list="[]",
        key_id="key-01",
        key_state="active",
        key_size=2048,
        key_creation_date=datetime(2026, 1, 1, 0, 0, 0),
        key_activation_date=datetime(2026, 1, 2, 0, 0, 0),
        protocol_name="TLS",
        protocol_version_name="TLS 1.3",
        cipher_suites="TLS_AES_128_GCM_SHA256",
        subject_name="CN=example.org",
        issuer_name="CN=Example Root CA",
        not_valid_before=datetime(2026, 1, 1, 0, 0, 0),
        not_valid_after=datetime(2027, 1, 1, 0, 0, 0),
        signature_algorithm_reference="SHA256withRSA",
        subject_public_key_reference="RSA-2048",
        certificate_format="X.509",
        certificate_extension=".crt",
        key_length=2048,
        protocol_version="TLS 1.3",
        nist_status="quantum-vulnerable",
        quantum_safe_flag=False,
        hndl_level="Medium",
    )

    row = format_cbom_entry_row(entry)

    assert row["asset_name"] == "example.org"
    assert row["asset_type"] == "algorithm"
    assert row["element_name"] == "AES-128-GCM"
    assert row["primitive"] == "block-cipher"
    assert row["mode"] == "gcm"
    assert row["oid"] == "2.16.840.1.101.3.4.1.6"
    assert row["protocol_name"] == "TLS"
    assert row["protocol_version_name"] == "TLS 1.3"
    assert row["signature_algorithm_reference"] == "SHA256withRSA"
    assert row["subject_public_key_reference"] == "RSA-2048"
    assert row["certificate_format"] == "X.509"
    assert row["certificate_extension"] == ".crt"
