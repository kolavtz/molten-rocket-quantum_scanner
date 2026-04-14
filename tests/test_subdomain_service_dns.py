import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.services import subdomain_service as svc


class _AnswerSet(list):
    pass


class _MX:
    def __init__(self, exchange: str):
        self.exchange = exchange

    def __str__(self):
        return str(self.exchange)


class _NS:
    def __init__(self, target: str):
        self.target = target

    def __str__(self):
        return str(self.target)


class _TXT:
    def __init__(self, value: str):
        self.value = value

    def __str__(self):
        return self.value


class _FakeResolver:
    def __init__(self):
        self.timeout = 0
        self.lifetime = 0
        self.nameservers = []

    def resolve(self, domain, record_type, lifetime=None):
        if record_type == "MX":
            return _AnswerSet([_MX("10 mail.example.com.")])
        if record_type == "NS":
            return _AnswerSet([_NS("ns1.example.com.")])
        if record_type == "TXT":
            return _AnswerSet([_TXT('"v=spf1 include:_spf.example.com ~all"')])
        if record_type == "A":
            return _AnswerSet(["203.0.113.10"])
        raise svc.dns.resolver.NoAnswer()


def test_collect_dns_candidates_via_dnspython_extracts_related_hosts(monkeypatch):
    resolver = _FakeResolver()
    monkeypatch.setattr(svc.dns.resolver, "Resolver", lambda: resolver)

    candidates = svc._collect_dns_candidates_via_dnspython("example.com")

    assert "mail.example.com" in candidates
    assert "ns1.example.com" in candidates
    assert "_spf.example.com" in candidates
    assert "203.0.113.10" not in candidates


def test_collect_dns_candidates_via_dnspython_respects_nameserver_override(monkeypatch):
    resolver = _FakeResolver()
    monkeypatch.setattr(svc.dns.resolver, "Resolver", lambda: resolver)
    monkeypatch.setenv("QSS_DNS_NAMESERVERS", "8.8.8.8,1.1.1.1")

    _ = svc._collect_dns_candidates_via_dnspython("example.com")

    assert resolver.nameservers == ["8.8.8.8", "1.1.1.1"]


def test_is_valid_subdomain_candidate_rejects_parent_and_accepts_real_subdomain():
    assert svc._is_valid_subdomain_candidate("portal.example.com", "example.com") is True
    assert svc._is_valid_subdomain_candidate("example.com", "example.com") is False


def test_wildcard_normalization_does_not_create_fake_subdomain_row():
    wildcard = "*.example.com"
    normalized = svc._normalize_domain_candidate(wildcard)
    assert normalized == "example.com"
    assert svc._is_valid_subdomain_candidate(normalized, "example.com") is False


def test_collect_common_subdomains_via_dns_discovers_concrete_hosts(monkeypatch):
    class _CommonResolver:
        def __init__(self):
            self.timeout = 0
            self.lifetime = 0
            self.nameservers = []

        def resolve(self, domain, record_type, lifetime=None):
            if domain == "www.example.com" and record_type == "A":
                return _AnswerSet(["203.0.113.10"])
            raise svc.dns.resolver.NoAnswer()

    monkeypatch.setattr(svc.dns.resolver, "Resolver", lambda: _CommonResolver())
    monkeypatch.setenv("QSS_SUBDOMAIN_WORDLIST", "www,api")

    discovered = svc._collect_common_subdomains_via_dns("example.com")
    assert "www.example.com" in discovered
    assert "api.example.com" not in discovered


def test_sync_from_certificate_soft_deletes_legacy_wildcard_rows(monkeypatch):
    wildcard_row = SimpleNamespace(is_deleted=False)
    normal_row = SimpleNamespace(is_deleted=False)

    class _FilterQuery:
        def __init__(self, rows):
            self._rows = rows

        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return self._rows[0] if self._rows else None

        def all(self):
            return self._rows

    class _FakeSession:
        def __init__(self):
            self.added = []
            self.committed = False

        def query(self, model):
            name = getattr(model, "__name__", "")
            if name == "Asset":
                return _FilterQuery([SimpleNamespace(id=1, target="example.com")])
            if name == "Subdomain":
                return _FilterQuery([wildcard_row])
            if name == "Certificate":
                return _FilterQuery([SimpleNamespace(subject_cn="*.example.com", san_domains="")])
            if name == "Scan":
                return _FilterQuery([SimpleNamespace(report_json={"dns_records": []})])
            return _FilterQuery([])

        def add(self, obj):
            self.added.append(obj)

        def commit(self):
            self.committed = True

        def rollback(self):
            self.committed = False

    fake_session = _FakeSession()
    monkeypatch.setattr(svc, "db_session", fake_session)
    monkeypatch.setattr(svc, "_collect_dns_candidates_via_dnspython", lambda _domain: set())
    monkeypatch.setattr(svc, "_collect_common_subdomains_via_dns", lambda _domain: set())

    created = svc.SubdomainService.sync_from_certificate(asset_id=1, scan_id=1)

    assert wildcard_row.is_deleted is True
    assert created == 0
