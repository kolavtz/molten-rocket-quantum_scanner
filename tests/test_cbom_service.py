"""
Unit tests for CbomService class.
"""
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch
import pytest

from src.services.cbom_service import CbomService


def make_query_mock():
    q = Mock()
    q.filter.return_value = q
    q.join.return_value = q
    q.group_by.return_value = q
    q.order_by.return_value = q
    q.limit.return_value = q
    q.count.return_value = 0
    q.scalar.return_value = 0
    q.all.return_value = []
    q.with_entities.return_value = q
    return q


@patch('src.services.cbom_service.db_session')
def test_get_cbom_dashboard_data_empty(mock_db_session):
    # All queries returning default zero/empty values should produce empty kpis and no rows
    mock_db_session.query.side_effect = lambda *args, **kwargs: make_query_mock()

    data = CbomService.get_cbom_dashboard_data(asset_id=None, start_date=None, end_date=None, limit=10)

    assert data['kpis']['total_applications'] == 0
    assert data['kpis']['sites_surveyed'] == 0
    assert data['kpis']['active_certificates'] == 0
    assert data['kpis']['weak_cryptography'] == 0
    assert data['kpis']['certificate_issues'] == 0
    assert data['key_length_distribution'] == {'No Data': 0}
    assert data['cipher_usage'] == {'No Data': 0}
    assert data['top_cas'] == {'No Data': 0}
    assert data['protocols'] == {'No Data': 0}
    assert data['applications'] == []


@patch('src.services.cbom_service.db_session')
def test_get_cbom_dashboard_data_weak_values(mock_db_session):
    q = make_query_mock()
    q.count.return_value = 1
    q.scalar.return_value = 1
    q.all.return_value = []
    mock_db_session.query.return_value = q

    data = CbomService.get_cbom_dashboard_data(asset_id=1, start_date=None, end_date=None, limit=10)

    assert data['kpis']['total_applications'] == 1
    assert data['kpis']['sites_surveyed'] == 1
    assert data['kpis']['active_certificates'] == 1
    assert data['kpis']['weak_cryptography'] == 4  # weak_tls+weak_key+expired+self_signed from expected query paths
    assert 'weakness_heatmap' in data


def test_find_report_tls_row_matches_endpoint_subject_and_issuer():
    scan = SimpleNamespace(
        report_json=json.dumps(
            {
                "tls_results": [
                    {
                        "host": "google.com",
                        "port": 443,
                        "subject_cn": "google.com",
                        "issuer": "GTS CA 1C3",
                        "valid_to": "2026-12-31T23:59:59+00:00",
                        "cert_sha256": "ABCDEF123456",
                        "certificate_details": {
                            "certificate_format": "X.509",
                            "fingerprint_sha256": "ABCDEF123456",
                        },
                    }
                ]
            }
        )
    )

    row = CbomService._find_report_tls_row(
        scan=scan,
        subject_cn="google.com",
        endpoint="google.com:443",
        issuer="GTS CA 1C3",
    )

    assert row.get("valid_to") == "2026-12-31T23:59:59+00:00"
    assert row.get("cert_sha256") == "ABCDEF123456"
    assert isinstance(row.get("certificate_details"), dict)


def test_certificate_details_from_cert_row_includes_x509_and_fingerprint():
    cert = SimpleNamespace(
        serial="0123",
        signature_algorithm="sha256WithRSAEncryption",
        issuer="Example CA",
        ca="Example CA",
        valid_from=None,
        valid_until=None,
        subject="CN=example.com",
        subject_cn="example.com",
        public_key_type="RSA",
        key_algorithm="RSA",
        key_length=2048,
        public_key_pem="",
        fingerprint_sha256="F00DBABE",
    )

    details = CbomService._certificate_details_from_cert_row(cert)

    assert details.get("certificate_format") == "X.509"
    assert details.get("fingerprint_sha256") == "F00DBABE"
    assert details.get("subject") == "CN=example.com"


def test_build_x509_minimum_payload_parses_dn_and_defaults():
    certificate_details = {
        "subject": "CN=devtunnels.ms,O=Microsoft Corporation",
        "issuer": "CN=Microsoft Azure RSA TLS Issuing CA 04,O=Microsoft Corporation",
        "validity": {
            "not_before": "2026-02-16T18:05:48+00:00",
            "not_after": "2026-08-15T18:05:48+00:00",
        },
        "fingerprint_sha256": "CERTFPR123",
        "subject_public_key_info": {},
    }

    payload = CbomService._build_x509_minimum_payload(
        certificate_details=certificate_details,
        subject_cn="",
        subject_o="",
        subject_ou="",
        issuer_cn="",
        issuer_o="",
        issuer_ou="",
        valid_from="",
        valid_until="",
        cert_fingerprint_sha256="",
        public_key_fingerprint_sha256="",
    )

    assert payload["issued_to"]["common_name"] == "devtunnels.ms"
    assert payload["issued_to"]["organization"] == "Microsoft Corporation"
    assert payload["issued_to"]["organizational_unit"] == "<Not Part Of Certificate>"
    assert payload["issued_by"]["common_name"] == "Microsoft Azure RSA TLS Issuing CA 04"
    assert payload["validity_period"]["expires_on"] == "2026-08-15T18:05:48+00:00"
    assert payload["sha256_fingerprints"]["certificate"] == "CERTFPR123"


def test_public_key_fingerprint_sha256_from_pem_returns_digest():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    digest = CbomService._public_key_fingerprint_sha256_from_pem(public_pem)

    assert isinstance(digest, str)
    assert len(digest) == 64
