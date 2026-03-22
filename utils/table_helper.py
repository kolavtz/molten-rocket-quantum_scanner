"""Shared pagination, filtering, and sorting helpers for inventory tables.

The helper accepts either a SQLAlchemy query or an in-memory sequence of
rows/dicts. That keeps the API usable for both fully database-backed views
and enriched table rows assembled after a light query.

Example:
    page_data = paginate_query(
        db_session.query(Asset).filter(Asset.is_deleted == False),
        page=1,
        page_size=25,
        sort="name",
        order="asc",
        search="example",
        searchable_columns=[Asset.name, Asset.url, Asset.owner],
    )
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date, datetime
from math import ceil
from typing import Any

from sqlalchemy import func, or_

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
ALLOWED_PAGE_SIZES = {10, 25, 50, 100}


def _normalize_page(value: Any) -> int:
    try:
        page = int(value or 1)
    except (TypeError, ValueError):
        return 1
    return max(1, page)


def _normalize_page_size(value: Any) -> int:
    try:
        page_size = int(value or DEFAULT_PAGE_SIZE)
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    page_size = max(1, min(MAX_PAGE_SIZE, page_size))
    if page_size not in ALLOWED_PAGE_SIZES:
        if page_size < 10:
            return 10
        if page_size < 25:
            return 25
        if page_size < 50:
            return 50
        return 100
    return page_size


def _normalize_order(value: Any) -> str:
    return "desc" if str(value or "asc").strip().lower() == "desc" else "asc"


def _resolve_row_value(row: Any, field_name: str) -> Any:
    if isinstance(row, dict):
        return row.get(field_name)
    if hasattr(row, field_name):
        return getattr(row, field_name)
    if hasattr(row, "_mapping"):
        mapping = getattr(row, "_mapping")
        if field_name in mapping:
            return mapping[field_name]
    return None


def _coerce_sort_value(value: Any) -> tuple[int, Any]:
    if value is None:
        return (1, "")
    if isinstance(value, (int, float)):
        return (0, value)
    if isinstance(value, (datetime, date)):
        return (0, value)
    text = str(value).strip().lower()
    if text == "":
        return (1, "")
    return (0, text)


def _sequence_matches_search(row: Any, columns: Sequence[Any], term: str) -> bool:
    if not term:
        return True
    lowered = term.lower()
    for column in columns:
        if isinstance(column, str):
            value = _resolve_row_value(row, column)
        else:
            value = _resolve_row_value(row, getattr(column, "key", str(column)))
        if value is None:
            continue
        if lowered in str(value).lower():
            return True
    return False


def _resolve_sort_attr(query: Any, sort_name: str) -> Any:
    if not sort_name:
        return None

    column_descriptions = getattr(query, "column_descriptions", []) or []
    for description in column_descriptions:
        expr = description.get("expr")
        entity = description.get("entity")
        if expr is not None:
            expr_key = getattr(expr, "key", None) or getattr(expr, "name", None)
            if expr_key == sort_name:
                return expr
        if entity is not None and hasattr(entity, sort_name):
            return getattr(entity, sort_name)

    if column_descriptions:
        first_entity = column_descriptions[0].get("entity")
        if first_entity is not None and hasattr(first_entity, sort_name):
            return getattr(first_entity, sort_name)
    return None


def _is_sqlalchemy_query(value: Any) -> bool:
    return hasattr(value, "filter") and hasattr(value, "count") and hasattr(value, "offset") and hasattr(value, "limit")


def _page_response(items: list[Any], total: int, page: int, page_size: int, sort: str, order: str, search: str) -> dict[str, Any]:
    total_pages = max(1, ceil(total / max(1, page_size)))
    page = min(max(1, page), total_pages)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = items[start:end]
    return {
        "items": sliced,
        "total": total,
        "total_count": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "start_index": start + 1 if total else 0,
        "end_index": min(end, total),
        "sort": sort,
        "order": order,
        "search": search,
    }


def paginate_query(
    query: Any,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    sort: str | None = None,
    order: str = "asc",
    search: str | None = None,
    searchable_columns: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Paginate a SQLAlchemy query or a sequence of rows."""

    page = _normalize_page(page)
    page_size = _normalize_page_size(page_size)
    sort = (sort or "").strip()
    order = _normalize_order(order)
    search = (search or "").strip()
    searchable_columns = list(searchable_columns or [])

    if _is_sqlalchemy_query(query):
        working_query = query
        if search and searchable_columns:
            search_terms = []
            for column in searchable_columns:
                if isinstance(column, str):
                    resolved = _resolve_sort_attr(query, column)
                    if resolved is None:
                        continue
                    column = resolved
                search_terms.append(func.lower(column).like(f"%{search.lower()}%"))
            if search_terms:
                working_query = working_query.filter(or_(*search_terms))

        sort_column = _resolve_sort_attr(working_query, sort)
        if sort_column is not None:
            working_query = working_query.order_by(sort_column.desc() if order == "desc" else sort_column.asc())

        total = int(working_query.order_by(None).count() or 0)
        items = list(working_query.offset((page - 1) * page_size).limit(page_size).all())
        return _page_response(items, total, page, page_size, sort, order, search)

    items = list(query or [])
    if search and searchable_columns:
        items = [row for row in items if _sequence_matches_search(row, searchable_columns, search)]

    if sort:
        items.sort(
            key=lambda row: _coerce_sort_value(_resolve_row_value(row, sort)),
            reverse=order == "desc",
        )

    total = len(items)
    return _page_response(items, total, page, page_size, sort, order, search)

