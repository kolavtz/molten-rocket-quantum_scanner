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
    cursor.fetchone.return_value = None
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
        # Should execute 4 SQL statements: CREATE DB, USE, CREATE scans, CREATE cbom_reports
        assert mock_cursor.execute.call_count == 4
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
        assert params[2] == "complete"       # status
        assert params[3] == 33               # compliance_score
        assert params[4] == 3                # total_assets
        assert params[5] == 1                # quantum_safe
        assert params[6] == 2                # quantum_vulnerable
        # params[7] is datetime, params[8] is JSON string
        assert json.loads(params[8])["scan_id"] == "abc12345"

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
        mock_cursor.fetchone.return_value = (json.dumps(SAMPLE_REPORT),)
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
            (json.dumps(SAMPLE_REPORT),),
            (json.dumps(report2),),
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
        mock_cursor.fetchone.return_value = (json.dumps(SAMPLE_CBOM),)
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
