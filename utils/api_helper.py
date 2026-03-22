from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from flask import jsonify, request
from sqlalchemy import or_


def to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def parse_paging_args(default_sort: str = "id") -> dict[str, Any]:
    page = max(1, request.args.get("page", 1, type=int) or 1)
    page_size = min(max(1, request.args.get("page_size", 25, type=int) or 25), 250)
    sort = str(request.args.get("sort", default_sort) or default_sort).strip()
    order = str(request.args.get("order", "asc") or "asc").strip().lower()
    q = str(request.args.get("q", "") or "").strip()
    return {
        "page": page,
        "page_size": page_size,
        "sort": sort,
        "order": "desc" if order == "desc" else "asc",
        "search": q,
    }


def apply_text_search(query, search: str, columns: list[Any]):
    if not search:
        return query
    return query.filter(or_(*[col.ilike(f"%{search}%") for col in columns]))


def apply_sort(query, sort_key: str, order: str, sort_map: dict[str, Any], fallback: Any):
    col = sort_map.get(sort_key, fallback)
    return query.order_by(col.desc() if order == "desc" else col.asc())


def build_data_envelope(items: list[dict[str, Any]], total: int, params: dict[str, Any], kpis: dict[str, Any] | None = None) -> dict[str, Any]:
    page = int(params.get("page", 1) or 1)
    page_size = int(params.get("page_size", 25) or 25)
    total_pages = max(1, math.ceil(max(0, int(total)) / max(1, page_size)))
    return {
        "items": items,
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "kpis": kpis or {},
    }


def success_response(data: dict[str, Any], filters: dict[str, Any] | None = None, status: int = 200, include_legacy_top_level: bool = True):
    payload: dict[str, Any] = {
        "success": True,
        "data": data,
        "filters": filters or {},
    }
    if include_legacy_top_level:
        payload.update(data)
    return jsonify(payload), status


def error_response(message: str, status: int = 500, hint: str | None = None):
    body: dict[str, Any] = {
        "success": False,
        "error": {
            "message": message,
            "status": status,
        },
    }
    if hint:
        body["error"]["hint"] = hint
    return jsonify(body), status
