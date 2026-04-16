"""Centralized SSL/TLS risk profiling helpers.

This module provides one consistent way to derive inventory risk levels
from scan telemetry so Scan Center and Inventory flows stay aligned.
"""

from __future__ import annotations

from typing import Any


WEAK_TLS_TOKENS = {"SSLV2", "SSLV3", "TLS1.0", "TLS1.1"}
WEAK_CIPHER_TOKENS = (
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "MD5",
)


def score_to_risk_level(score: float) -> str:
    """Map compliance/security score (0-100) to risk level."""
    normalized = float(score or 0)
    if normalized >= 80:
        return "Low"
    if normalized >= 60:
        return "Medium"
    if normalized >= 40:
        return "High"
    return "Critical"


def _safe_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalized_tls_version(raw: Any) -> str:
    return str(raw or "").strip().upper().replace(" ", "")


def _contains_weak_cipher(raw_cipher: Any, raw_cipher_list: Any) -> bool:
    candidates: list[str] = []
    if isinstance(raw_cipher_list, list):
        candidates.extend(str(item or "").upper() for item in raw_cipher_list)
    cipher_text = str(raw_cipher or "").upper()
    if cipher_text:
        candidates.append(cipher_text)

    if not candidates:
        return False

    joined = " ".join(candidates)
    return any(token in joined for token in WEAK_CIPHER_TOKENS)


def _telemetry_score(tls_results: list[dict[str, Any]]) -> float | None:
    """Compute a conservative score from TLS telemetry rows."""
    if not tls_results:
        return None

    score = 100.0
    has_weak_tls = False
    has_weak_key = False
    has_expired = False
    has_self_signed = False
    has_weak_cipher = False

    for row in tls_results:
        if not isinstance(row, dict):
            continue

        tls_version = _normalized_tls_version(row.get("tls_version") or row.get("protocol_version"))
        if tls_version in WEAK_TLS_TOKENS:
            has_weak_tls = True

        key_len = _safe_int(row.get("key_length") or row.get("key_size"))
        if key_len is not None and 0 < key_len < 2048:
            has_weak_key = True

        cert_expired = bool(row.get("cert_expired") or row.get("is_expired"))
        cert_days = _safe_int(row.get("cert_days_remaining") or row.get("days_remaining"))
        if cert_expired or (cert_days is not None and cert_days < 0):
            has_expired = True

        if bool(row.get("is_self_signed")):
            has_self_signed = True

        if _contains_weak_cipher(row.get("cipher_suite"), row.get("cipher_suites") or row.get("all_cipher_suites")):
            has_weak_cipher = True

    if has_weak_tls:
        score -= 30
    if has_weak_key:
        score -= 25
    if has_expired:
        score -= 20
    if has_self_signed:
        score -= 10
    if has_weak_cipher:
        score -= 15

    return max(0.0, min(100.0, score))


def derive_risk_level(
    *,
    overview_score: Any = None,
    tls_results: Any = None,
    fallback: str = "Medium",
) -> str:
    """Derive risk level from overview score and TLS telemetry.

    Uses conservative composition when both values are present:
    choose the lower (riskier) of overview and telemetry scores.
    """
    overview_val = _safe_float(overview_score)
    tls_rows = tls_results if isinstance(tls_results, list) else []
    telemetry_val = _telemetry_score(tls_rows)

    chosen_score: float | None = None
    if overview_val is not None and telemetry_val is not None:
        chosen_score = min(overview_val, telemetry_val)
    elif overview_val is not None:
        chosen_score = overview_val
    elif telemetry_val is not None:
        chosen_score = telemetry_val

    if chosen_score is None:
        return str(fallback or "Medium").strip() or "Medium"

    return score_to_risk_level(chosen_score)


def derive_risk_level_from_scan_report(report: dict[str, Any] | None, fallback: str = "Medium") -> str:
    """Derive risk level directly from a scan report payload."""
    data = report if isinstance(report, dict) else {}
    overview = data.get("overview") if isinstance(data.get("overview"), dict) else {}
    overview_score = overview.get("average_compliance_score")
    if overview_score is None:
        overview_score = data.get("overall_pqc_score")

    return derive_risk_level(
        overview_score=overview_score,
        tls_results=data.get("tls_results"),
        fallback=fallback,
    )
