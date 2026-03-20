"""
Unit tests for src/database.py — MySQL Redundant Storage

All tests use mocked MySQL connections so they run without a live
database.  The tests verify:
    - init_db creates database and tables
    - save_scan inserts with correct params
    - save_cbom inserts with correct params
    - get_scan returns deserialized JSON
    - list_scans returns ordered results
    - get_cbom returns deserialized JSON
    - graceful fallback when MySQL is unavailable
"""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Fixtures ─────────────────────────────────────────────────────────

SAMPLE_REPORT = {
    "scan_id": "abc12345",
    "target": "example.com",
    "asset_class": "Public Web Application",
    "status": "complete",
    "generated_at": "2026-03-10T12:00:00+00:00",
    "overview": {
        "total_assets": 3,
        "quantum_safe": 1,
        "quantum_vulnerable": 2,
        "average_compliance_score": 33,
    },
    "tls_results": [{"host": "example.com", "port": 443}],
    "findings": [{"severity": "HIGH", "description": "Weak key exchange"}],
}

SAMPLE_CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"name": "TLS1.3-ECDHE", "type": "cryptographic-asset"}],
}


@pytest.fixture
def mock_cursor():
    """Create a mock cursor with common attributes."""
    cursor = MagicMock()
    cursor.fetchone.return_value = (0,)
    cursor.fetchall.return_value = []
    return cursor


@pytest.fixture
def mock_conn(mock_cursor):
    """Create a mock connection that returns the mock cursor."""
    conn = MagicMock()
    conn.cursor.return_value = mock_cursor
    return conn


# ── init_db ──────────────────────────────────────────────────────────

class TestInitDb:
    @patch("src.database._get_server_connection")
    def test_init_db_creates_tables(self, mock_get_conn, mock_conn, mock_cursor):
        """init_db should create the database and both tables."""
        mock_get_conn.return_value = mock_conn
        from src.database import init_db

        result = init_db()

        assert result is True
        # Should execute CREATE DB, USE, CREATE tables, ALTER tables, etc.
        assert mock_cursor.execute.call_count >= 4
        mock_conn.commit.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch("src.database._get_server_connection")
    def test_init_db_unavailable(self, mock_get_conn):
        """init_db should return False when MySQL is unavailable."""
        mock_get_conn.return_value = None
        from src.database import init_db

        result = init_db()

        assert result is False

    @patch("src.database._get_server_connection")
    def test_init_db_handles_sql_error(self, mock_get_conn, mock_conn, mock_cursor):
        """init_db should return False and close connection on SQL error."""
        mock_get_conn.return_value = mock_conn
        mock_cursor.execute.side_effect = Exception("SQL syntax error")
        from src.database import init_db

        result = init_db()

        assert result is False
        mock_conn.close.assert_called_once()

    @patch("src.database._get_server_connection")
    def test_init_db_runs_legacy_scans_compatibility_migrations(self, mock_get_conn, mock_conn, mock_cursor):
        """init_db should execute scan schema compatibility SQL for legacy DBs."""
        mock_get_conn.return_value = mock_conn
        from src.database import init_db

        result = init_db()

        assert result is True
        executed_sql = "\n".join(call_args[0][0] for call_args in mock_cursor.execute.call_args_list)
        assert "ALTER TABLE scans ADD COLUMN scan_id VARCHAR(36)" in executed_sql
        assert "ALTER TABLE scans ADD COLUMN report_json LONGTEXT NOT NULL" in executed_sql
        assert "UPDATE scans SET scan_id = UUID()" in executed_sql


# ── save_scan ────────────────────────────────────────────────────────

class TestSaveScan:
    @patch("src.database._get_connection")
    def test_save_scan_success(self, mock_get_conn, mock_conn, mock_cursor):
        """save_scan should INSERT the report with correct structured params."""
        mock_get_conn.return_value = mock_conn
        from src.database import save_scan

        result = save_scan(SAMPLE_REPORT)

        assert result is True
        mock_cursor.execute.assert_called_once()
        sql = mock_cursor.execute.call_args[0][0]
        params = mock_cursor.execute.call_args[0][1]

        assert "INSERT INTO scans" in sql
        assert params[0] == "abc12345"       # scan_id
        assert params[1] == "example.com"    # target
        assert params[2] == "Public Web Application"  # asset_class
        assert params[3] == "complete"       # status
        assert params[4] == 33               # compliance_score
        assert params[5] == 3                # total_assets
        assert params[6] == 1                # quantum_safe
        assert params[7] == 2                # quantum_vulnerable
        # params[8] is datetime, params[9] is JSON string, params[10] is is_encrypted
        assert json.loads(params[9])["scan_id"] == "abc12345"
        assert params[10] is False

        mock_conn.commit.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch("src.database._get_connection")
    def test_save_scan_unavailable(self, mock_get_conn):
        """save_scan should return False when MySQL is unavailable."""
        mock_get_conn.return_value = None
        from src.database import save_scan

        result = save_scan(SAMPLE_REPORT)

        assert result is False

    @patch("src.database._get_connection")
    def test_save_scan_handles_error(self, mock_get_conn, mock_conn, mock_cursor):
        """save_scan should return False on SQL error and close connection."""
        mock_get_conn.return_value = mock_conn
        mock_cursor.execute.side_effect = Exception("Duplicate entry")
        from src.database import save_scan

        result = save_scan(SAMPLE_REPORT)

        assert result is False
        mock_conn.close.assert_called_once()


# ── save_cbom ────────────────────────────────────────────────────────

class TestSaveCbom:
    @patch("src.database._get_connection")
    def test_save_cbom_success(self, mock_get_conn, mock_conn, mock_cursor):
        """save_cbom should INSERT the CBOM JSON with correct scan_id."""
        mock_get_conn.return_value = mock_conn
        from src.database import save_cbom

        result = save_cbom("abc12345", SAMPLE_CBOM)

        assert result is True
        sql = mock_cursor.execute.call_args[0][0]
        params = mock_cursor.execute.call_args[0][1]
        assert "INSERT INTO cbom_reports" in sql
        assert params[0] == "abc12345"
        assert json.loads(params[1])["bomFormat"] == "CycloneDX"
        assert params[2] is False
        mock_conn.commit.assert_called_once()

    @patch("src.database._get_connection")
    def test_save_cbom_unavailable(self, mock_get_conn):
        """save_cbom should return False when MySQL is unavailable."""
        mock_get_conn.return_value = None
        from src.database import save_cbom

        result = save_cbom("abc12345", SAMPLE_CBOM)

        assert result is False


# ── get_scan ─────────────────────────────────────────────────────────

class TestGetScan:
    @patch("src.database._get_connection")
    def test_get_scan_found(self, mock_get_conn, mock_conn, mock_cursor):
        """get_scan should return deserialized report dict."""
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchone.return_value = (json.dumps(SAMPLE_REPORT), False)
        from src.database import get_scan

        result = get_scan("abc12345")

        assert result is not None
        assert result["scan_id"] == "abc12345"
        assert result["target"] == "example.com"
        mock_conn.close.assert_called_once()

    @patch("src.database._get_connection")
    def test_get_scan_not_found(self, mock_get_conn, mock_conn, mock_cursor):
        """get_scan should return None when scan_id doesn't exist."""
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchone.return_value = None
        from src.database import get_scan

        result = get_scan("nonexistent")

        assert result is None

    @patch("src.database._get_connection")
    def test_get_scan_unavailable(self, mock_get_conn):
        """get_scan should return None when MySQL is unavailable."""
        mock_get_conn.return_value = None
        from src.database import get_scan

        result = get_scan("abc12345")

        assert result is None


# ── list_scans ───────────────────────────────────────────────────────

class TestListScans:
    @patch("src.database._get_connection")
    def test_list_scans_returns_reports(self, mock_get_conn, mock_conn, mock_cursor):
        """list_scans should return a list of deserialized reports."""
        report2 = {**SAMPLE_REPORT, "scan_id": "def67890", "target": "github.com"}
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchall.return_value = [
            (json.dumps(SAMPLE_REPORT), False),
            (json.dumps(report2), False),
        ]
        from src.database import list_scans

        results = list_scans(limit=10)

        assert len(results) == 2
        assert results[0]["scan_id"] == "abc12345"
        assert results[1]["scan_id"] == "def67890"
        # Verify LIMIT is passed
        sql = mock_cursor.execute.call_args[0][0]
        assert "LIMIT" in sql

    @patch("src.database._get_connection")
    def test_list_scans_empty(self, mock_get_conn, mock_conn, mock_cursor):
        """list_scans should return empty list when no scans exist."""
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchall.return_value = []
        from src.database import list_scans

        results = list_scans()

        assert results == []

    @patch("src.database._get_connection")
    def test_list_scans_unavailable(self, mock_get_conn):
        """list_scans should return empty list when MySQL is unavailable."""
        mock_get_conn.return_value = None
        from src.database import list_scans

        results = list_scans()

        assert results == []


# ── get_cbom ─────────────────────────────────────────────────────────

class TestGetCbom:
    @patch("src.database._get_connection")
    def test_get_cbom_found(self, mock_get_conn, mock_conn, mock_cursor):
        """get_cbom should return deserialized CBOM dict."""
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchone.return_value = (json.dumps(SAMPLE_CBOM), False)
        from src.database import get_cbom

        result = get_cbom("abc12345")

        assert result is not None
        assert result["bomFormat"] == "CycloneDX"

    @patch("src.database._get_connection")
    def test_get_cbom_not_found(self, mock_get_conn, mock_conn, mock_cursor):
        """get_cbom should return None when scan_id doesn't exist."""
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchone.return_value = None
        from src.database import get_cbom

        result = get_cbom("nonexistent")

        assert result is None

    @patch("src.database._get_connection")
    def test_get_cbom_unavailable(self, mock_get_conn):
        """get_cbom should return None when MySQL is unavailable."""
        mock_get_conn.return_value = None
        from src.database import get_cbom

        result = get_cbom("abc12345")

        assert result is None


class TestDnsRecords:
    @patch("src.database._get_connection")
    def test_save_dns_records_success(self, mock_get_conn, mock_conn, mock_cursor):
        mock_get_conn.return_value = mock_conn
        from src.database import save_dns_records

        records = [
            {
                "hostname": "example.com",
                "record_type": "A",
                "record_value": "93.184.216.34",
                "ttl": 300,
                "resolved_at": "2026-03-15T10:00:00Z",
            }
        ]

        result = save_dns_records("abc12345", records)

        assert result is True
        assert mock_cursor.execute.call_count == 2
        first_sql = mock_cursor.execute.call_args_list[0][0][0]
        second_sql = mock_cursor.execute.call_args_list[1][0][0]
        assert "DELETE FROM asset_dns_records" in first_sql
        assert "INSERT INTO asset_dns_records" in second_sql

    @patch("src.database._get_connection")
    def test_list_dns_records(self, mock_get_conn, mock_conn, mock_cursor):
        mock_get_conn.return_value = mock_conn
        cur_dict = MagicMock()
        cur_dict.fetchall.return_value = [
            {
                "scan_id": "abc12345",
                "hostname": "example.com",
                "record_type": "A",
                "record_value": "93.184.216.34",
                "ttl": 300,
                "resolved_at": datetime(2026, 3, 15, 10, 0, 0),
            }
        ]
        mock_conn.cursor.return_value = cur_dict
        from src.database import list_dns_records

        rows = list_dns_records("abc12345")

        assert len(rows) == 1
        assert rows[0]["hostname"] == "example.com"
        assert rows[0]["record_type"] == "A"
