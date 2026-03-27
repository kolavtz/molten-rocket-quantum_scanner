"""Incident service for API-first incident workflows.

Backs incident endpoints using findings as the persisted source of truth,
with workflow metadata stored in ``findings.metadata_json``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from sqlalchemy import func, inspect
from sqlalchemy.exc import SQLAlchemyError

from src.db import db_session
from src.models import Finding


class IncidentService:
    """CRUD-style incident operations backed by ``findings`` rows."""

    VALID_SEVERITIES = {"critical", "high", "medium", "low"}
    VALID_STATUSES = {"new", "in progress", "resolved", "closed", "reopened"}

    @staticmethod
    def _findings_table_available() -> bool:
        """Return ``True`` when the findings table exists in the active DB bind."""
        try:
            bind = db_session.get_bind()
            if bind is None:
                return False
            return bool(inspect(bind).has_table("findings"))
        except Exception:
            return False

    @staticmethod
    def _to_iso(value: Any) -> str | None:
        if value is None:
            return None
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _safe_metadata(raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return dict(raw)
        text = str(raw or "").strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return {}

    @classmethod
    def _normalize_severity(cls, value: Any, default: str = "medium") -> str:
        text = str(value or "").strip().lower()
        if text in cls.VALID_SEVERITIES:
            return text
        return default

    @classmethod
    def _normalize_status(cls, value: Any, default: str = "new") -> str:
        text = str(value or "").strip().lower()
        aliases = {
            "in_progress": "in progress",
            "in-progress": "in progress",
        }
        normalized = aliases.get(text, text)
        if normalized in cls.VALID_STATUSES:
            return normalized
        return default

    @classmethod
    def _finding_to_incident(cls, finding: Finding) -> Dict[str, Any]:
        meta = cls._safe_metadata(getattr(finding, "metadata_json", None))

        issue_type = str(getattr(finding, "issue_type", "") or "incident")
        title = str(meta.get("title") or issue_type.replace("_", " ").title())
        category = str(meta.get("category") or issue_type)
        status = cls._normalize_status(meta.get("status"), default="new")
        severity = cls._normalize_severity(getattr(finding, "severity", ""), default="medium")

        timeline = meta.get("timeline")
        if not isinstance(timeline, list):
            timeline = []

        notes = meta.get("notes")
        if not isinstance(notes, list):
            notes = []

        tags = meta.get("tags")
        if not isinstance(tags, list):
            tags = []

        return {
            "incident_id": str(getattr(finding, "finding_id", "") or getattr(finding, "id", "")),
            "title": title,
            "category": category,
            "severity": severity,
            "source_system": str(meta.get("source_system") or "system"),
            "status": status.title() if status != "in progress" else "In Progress",
            "owner": str(meta.get("owner") or ""),
            "created_at": cls._to_iso(getattr(finding, "created_at", None)),
            "last_updated_at": cls._to_iso(getattr(finding, "updated_at", None)),
            "description": str(getattr(finding, "description", "") or ""),
            "tags": [str(tag) for tag in tags],
            "notes": notes,
            "timeline": timeline,
            "linked_entities": {
                "asset_id": getattr(finding, "asset_id", None),
                "scan_id": getattr(finding, "scan_id", None),
                "certificate_id": getattr(finding, "certificate_id", None),
                "cbom_entry_id": getattr(finding, "cbom_entry_id", None),
            },
        }

    @classmethod
    def list_incidents(
        cls,
        page: int = 1,
        page_size: int = 25,
        sort: str = "created_at",
        order: str = "desc",
        search: str = "",
        severity: str = "",
        status: str = "",
        category: str = "",
    ) -> Tuple[Dict[str, Any], int]:
        if not cls._findings_table_available():
            return {
                "items": [],
                "total": 0,
                "page": page,
                "page_size": page_size,
                "total_pages": 0,
                "kpis": {
                    "total_incidents": 0,
                    "critical_incidents": 0,
                },
            }, 200

        query = db_session.query(Finding).filter(Finding.is_deleted == False)

        sev = cls._normalize_severity(severity, default="") if severity else ""
        if sev:
            query = query.filter(func.lower(Finding.severity) == sev)

        if category:
            query = query.filter(func.lower(Finding.issue_type) == str(category).strip().lower())

        if search:
            like = f"%{str(search).strip()}%"
            query = query.filter(
                Finding.description.ilike(like) | Finding.issue_type.ilike(like) | Finding.finding_id.ilike(like)
            )

        sort_field = (sort or "created_at").strip().lower()
        sort_map = {
            "incident_id": Finding.finding_id,
            "severity": Finding.severity,
            "category": Finding.issue_type,
            "created_at": Finding.created_at,
            "last_updated_at": Finding.updated_at,
        }
        sort_column = sort_map.get(sort_field, Finding.created_at)
        query = query.order_by(sort_column.desc() if str(order).lower() == "desc" else sort_column.asc())

        total = int(query.count() or 0)
        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 25), 100))
        offset = (page - 1) * page_size

        rows = query.offset(offset).limit(page_size).all()
        incidents = [cls._finding_to_incident(row) for row in rows]

        if status:
            status_norm = cls._normalize_status(status, default="")
            if status_norm:
                incidents = [
                    item
                    for item in incidents
                    if cls._normalize_status(item.get("status", ""), default="") == status_norm
                ]

        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        critical_incidents = int(
            db_session.query(func.count(Finding.id))
            .filter(Finding.is_deleted == False, func.lower(Finding.severity) == "critical")
            .scalar()
            or 0
        )

        data = {
            "items": incidents,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "kpis": {
                "total_incidents": total,
                "critical_incidents": critical_incidents,
            },
        }
        return data, 200

    @classmethod
    def get_incident(cls, incident_id: str) -> Tuple[Dict[str, Any] | None, int]:
        if not cls._findings_table_available():
            return None, 404

        candidate = str(incident_id or "").strip()
        if not candidate:
            return None, 404

        query = db_session.query(Finding).filter(Finding.is_deleted == False)
        finding = query.filter(Finding.finding_id == candidate).first()
        if finding is None and candidate.isdigit():
            finding = query.filter(Finding.id == int(candidate)).first()

        if finding is None:
            return None, 404

        return cls._finding_to_incident(finding), 200

    @classmethod
    def create_incident(cls, payload: Dict[str, Any], actor: str = "system") -> Tuple[Dict[str, Any], int]:
        if not cls._findings_table_available():
            return {"message": "Incident storage unavailable"}, 503

        title = str(payload.get("title") or "").strip()
        description = str(payload.get("description") or "").strip()
        category = str(payload.get("category") or "manual_incident").strip().lower()
        severity = cls._normalize_severity(payload.get("severity"), default="medium")

        if not title:
            return {"message": "title is required"}, 400

        metadata = {
            "title": title,
            "category": category,
            "status": cls._normalize_status(payload.get("status"), default="new"),
            "owner": str(payload.get("owner") or "").strip(),
            "source_system": str(payload.get("source_system") or "manual").strip(),
            "tags": payload.get("tags") if isinstance(payload.get("tags"), list) else [],
            "notes": payload.get("notes") if isinstance(payload.get("notes"), list) else [],
            "timeline": [
                {
                    "event": "created",
                    "actor": str(actor or "system"),
                    "at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        }

        finding = Finding(
            asset_id=payload.get("asset_id") if isinstance(payload.get("asset_id"), int) else None,
            scan_id=payload.get("scan_id") if isinstance(payload.get("scan_id"), int) else None,
            issue_type=category,
            severity=severity,
            description=description or title,
            metadata_json=json.dumps(metadata),
        )

        try:
            db_session.add(finding)
            db_session.commit()
        except SQLAlchemyError as exc:
            db_session.rollback()
            return {"message": "Failed to create incident", "hint": str(exc)}, 500

        return cls._finding_to_incident(finding), 201

    @classmethod
    def update_incident(cls, incident_id: str, payload: Dict[str, Any], actor: str = "system") -> Tuple[Dict[str, Any] | None, int]:
        if not cls._findings_table_available():
            return None, 404

        candidate = str(incident_id or "").strip()
        query = db_session.query(Finding).filter(Finding.is_deleted == False)
        finding = query.filter(Finding.finding_id == candidate).first()
        if finding is None and candidate.isdigit():
            finding = query.filter(Finding.id == int(candidate)).first()

        if finding is None:
            return None, 404

        metadata = cls._safe_metadata(getattr(finding, "metadata_json", None))

        if "severity" in payload:
            finding.severity = cls._normalize_severity(payload.get("severity"), default=finding.severity or "medium")
        if "description" in payload:
            finding.description = str(payload.get("description") or "").strip() or finding.description
        if "category" in payload:
            finding.issue_type = str(payload.get("category") or "").strip().lower() or finding.issue_type

        if "title" in payload:
            metadata["title"] = str(payload.get("title") or "").strip()
        if "status" in payload:
            metadata["status"] = cls._normalize_status(payload.get("status"), default=metadata.get("status") or "new")
        if "owner" in payload:
            metadata["owner"] = str(payload.get("owner") or "").strip()
        if "source_system" in payload:
            metadata["source_system"] = str(payload.get("source_system") or "").strip()
        if "tags" in payload and isinstance(payload.get("tags"), list):
            metadata["tags"] = payload.get("tags")
        if "notes" in payload and isinstance(payload.get("notes"), list):
            metadata["notes"] = payload.get("notes")

        timeline = metadata.get("timeline")
        if not isinstance(timeline, list):
            timeline = []
        timeline.append(
            {
                "event": "updated",
                "actor": str(actor or "system"),
                "at": datetime.now(timezone.utc).isoformat(),
                "fields": sorted([str(key) for key in payload.keys()]),
            }
        )
        metadata["timeline"] = timeline

        finding.metadata_json = json.dumps(metadata)

        try:
            db_session.commit()
        except SQLAlchemyError:
            db_session.rollback()
            return None, 500

        return cls._finding_to_incident(finding), 200
