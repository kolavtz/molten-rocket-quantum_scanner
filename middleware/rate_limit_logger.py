"""
Rate Limit Violation Logger — Sprint 2 Security Hardening

Provides an on_breach callback for Flask-Limiter that writes rate-limit
violations to the audit_log table. This creates a searchable paper trail
for security analysis and IP blocking decisions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def log_rate_limit_violation(request_limit, request) -> None:  # type: ignore[no-untyped-def]
    """
    Called by Flask-Limiter when a request exceeds a rate limit.

    Writes a record to the audit_logs table (best-effort; swallows all
    exceptions to prevent limiter from failing the real request).
    """
    try:
        from src import database as _db

        ip = (
            (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            or request.headers.get("X-Real-IP")
            or getattr(request, "remote_addr", "unknown")
            or "unknown"
        )

        _db.append_audit_log(
            event_category="security",
            event_type="rate_limit_exceeded",
            status="blocked",
            ip_address=ip,
            user_agent=(request.headers.get("User-Agent", "") or "")[:512],
            request_method=getattr(request, "method", "UNKNOWN"),
            request_path=getattr(request, "path", "UNKNOWN"),
            details={
                "limit": str(getattr(request_limit, "limit", "unknown")),
                "key": str(getattr(request_limit, "key", "unknown")),
                "reset_at": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception as exc:
        logger.debug("Rate-limit audit log write failed (non-critical): %s", exc)
