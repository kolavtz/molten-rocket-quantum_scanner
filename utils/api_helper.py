"""
Universal API response and pagination helper for QuantumShield.
Ensures all endpoints return consistent JSON structure.
"""

from typing import Any, Dict, List, Optional, Tuple
from flask import request
from sqlalchemy import func
import math


def validate_pagination_params(page: int = 1, page_size: int = 25) -> Tuple[int, int]:
    """Validate and normalize pagination parameters."""
    page = max(1, int(page) if isinstance(page, (int, str)) else 1)
    page_size = min(100, max(1, int(page_size) if isinstance(page_size, (int, str)) else 25))
    return page, page_size


def validate_sort_params(
    sort_field: Optional[str],
    order: str = "asc",
    allowed_fields: Optional[List[str]] = None
) -> Tuple[Optional[str], str]:
    """Validate sort field and order direction."""
    order = order.lower() if order else "asc"
    if order not in ["asc", "desc"]:
        order = "asc"
    
    if sort_field and allowed_fields and sort_field not in allowed_fields:
        return None, order
    
    return sort_field, order


def api_response(
    success: bool = True,
    message: str = "",
    data: Optional[Dict[str, Any]] = None,
    status_code: int = 200,
    filters: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Standard API response formatter.
    
    Returns:
        Tuple of (response_dict, status_code) for Flask
    """
    response = {
        "success": success,
        "data": data or {},
        "filters": filters or {}
    }
    
    if message:
        response["message"] = message
    
    return response, status_code


def paginated_response(
    items: List[Any],
    total: int,
    page: int,
    page_size: int,
    kpis: Optional[Dict[str, Any]] = None,
    filters: Optional[Dict[str, Any]] = None,
    status_code: int = 200
) -> Tuple[Dict[str, Any], int]:
    """
    Standardized paginated response with KPIs.
    
    Args:
        items: List of records for current page
        total: Total count of all records
        page: Current page number
        page_size: Records per page
        kpis: Optional dictionary of key performance indicators
        filters: Optional dictionary of applied filters
        status_code: HTTP status code
    
    Returns:
        Tuple of (response_dict, status_code)
    """
    total_pages = math.ceil(total / page_size) if page_size > 0 else 0
    
    data = {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }
    
    if kpis:
        data["kpis"] = kpis
    
    return {
        "success": True,
        "data": data,
        "filters": filters or {}
    }, status_code


def apply_soft_delete_filter(query):
    """Filter out soft-deleted records from query."""
    # Try to filter on is_deleted column if it exists on the model
    try:
        model_class = query.column_descriptions[0]["entity"]
        if hasattr(model_class, "is_deleted"):
            query = query.filter(model_class.is_deleted == False)
    except (IndexError, AttributeError, KeyError):
        pass
    return query


def get_query_pagination(query, page: int = 1, page_size: int = 25):
    """
    Apply pagination to a query and return items + total count.
    
    Args:
        query: SQLAlchemy query object
        page: Page number (1-indexed)
        page_size: Records per page
    
    Returns:
        Tuple of (items, total_count)
    """
    page, page_size = validate_pagination_params(page, page_size)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()
    
    return items, total, page, page_size


def search_filter(model, search_query: str, searchable_fields: List[str]):
    """
    Create a filter for searching multiple fields.
    
    Args:
        model: SQLAlchemy model class
        search_query: Search string
        searchable_fields: List of field names to search
    
    Returns:
        SQLAlchemy filter condition
    """
    if not search_query:
        return True
    
    search_term = f"%{search_query}%"
    conditions = []
    
    for field_name in searchable_fields:
        if hasattr(model, field_name):
            field = getattr(model, field_name)
            conditions.append(field.ilike(search_term))
    
    if conditions:
        from sqlalchemy import or_
        return or_(*conditions)
    
    return True


def format_datetime(dt, fmt: str = "%Y-%m-%d %H:%M:%S") -> Optional[str]:
    """Format datetime object to string."""
    if dt is None:
        return None
    return dt.strftime(fmt) if hasattr(dt, "strftime") else str(dt)


def format_asset_row(asset) -> Dict[str, Any]:
    """Convert Asset ORM object to dictionary for JSON response."""
    return {
        "id": asset.id,
        "asset_name": asset.target,
        "url": asset.url or "",
        "type": asset.asset_type or "",
        "owner": asset.owner or "",
        "risk_level": asset.risk_level or "unknown",
        "last_scan": format_datetime(asset.created_at) if asset.created_at else None,
        "created_at": format_datetime(asset.created_at),
        "updated_at": format_datetime(asset.updated_at)
    }


def format_certificate_row(cert) -> Dict[str, Any]:
    """Convert Certificate ORM object to dictionary for JSON response."""
    return {
        "id": cert.id,
        "subject": cert.subject or "",
        "issuer": cert.issuer or "",
        "key_length": cert.key_length or 0,
        "cipher_suite": cert.cipher_suite or "",
        "tls_version": cert.tls_version or "",
        "valid_until": format_datetime(cert.valid_until),
        "is_expired": cert.is_expired,
        "ca": cert.ca_name or cert.ca or ""
    }


def format_cbom_entry_row(entry) -> Dict[str, Any]:
    """Convert CBOMEntry ORM object to dictionary for JSON response."""
    return {
        "id": entry.id,
        "algorithm_name": entry.algorithm_name or "",
        "category": entry.category or "",
        "key_length": entry.key_length or 0,
        "protocol_version": entry.protocol_version or "",
        "nist_status": entry.nist_status or "",
        "quantum_safe": entry.quantum_safe_flag,
        "hndl_level": entry.hndl_level or ""
    }


def format_pqc_classification_row(pqc) -> Dict[str, Any]:
    """Convert PQCClassification ORM object to dictionary for JSON response."""
    return {
        "id": pqc.id,
        "algorithm_name": pqc.algorithm_name or "",
        "algorithm_type": pqc.algorithm_type or "",
        "quantum_safe_status": pqc.quantum_safe_status or "unknown",
        "nist_category": pqc.nist_category or "",
        "pqc_score": pqc.pqc_score or 0.0
    }


def extract_pagination_params(request_obj=None) -> Dict[str, Any]:
    """Extract pagination params from Flask request."""
    if request_obj is None:
        request_obj = request
    
    page = request_obj.args.get("page", 1, type=int)
    page_size = request_obj.args.get("page_size", 25, type=int)
    sort = request_obj.args.get("sort", None, type=str)
    order = request_obj.args.get("order", "asc", type=str)
    q = request_obj.args.get("q", "", type=str)
    
    return {
        "page": page,
        "page_size": page_size,
        "sort": sort,
        "order": order,
        "search": q
    }


def error_response(message: str, status_code: int = 400, hint: str = "") -> Tuple[Dict[str, Any], int]:
    """
    Standard error response formatter.
    
    Args:
        message: User-friendly error message
        status_code: HTTP status code
        hint: Optional hint for debugging
    
    Returns:
        Tuple of (response_dict, status_code)
    """
    response = {
        "success": False,
        "error": {
            "status": status_code,
            "message": message
        }
    }
    
    if hint:
        response["error"]["hint"] = hint
    
    return response, status_code


def success_response(data: Dict[str, Any], filters: Optional[Dict[str, Any]] = None, status_code: int = 200) -> Tuple[Dict[str, Any], int]:
    """
    Standard success response formatter.
    
    Args:
        data: Response data object
        filters: Optional applied filters
        status_code: HTTP status code
    
    Returns:
        Tuple of (response_dict, status_code)
    """
    response = {
        "success": True,
        "data": data,
        "filters": filters or {}
    }
    
    return response, status_code


def build_data_envelope(items: List[Any], total: int, params: Dict[str, Any], kpis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build standard data envelope for paginated responses.
    
    Args:
        items: List of items for current page
        total: Total number of items
        params: Pagination params dict with page, page_size, sort, order
        kpis: Optional KPIs dict
    
    Returns:
        Standardized data envelope dict
    """
    page = params.get("page", 1)
    page_size = params.get("page_size", 25)
    total_pages = math.ceil(total / page_size) if page_size > 0 else 1
    
    envelope = {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "kpis": kpis or {},
    }

    return envelope


def parse_paging_args(request_obj=None, default_sort: str = "id") -> Dict[str, Any]:
    """
    Parse pagination arguments from Flask request.
    
    Args:
        request_obj: Flask request object (defaults to current request)
        default_sort: Default sort field
    
    Returns:
        Dict with page, page_size, sort, order, search
    """
    if request_obj is None:
        request_obj = request
    
    page = request_obj.args.get("page", 1, type=int)
    page_size = request_obj.args.get("page_size", 25, type=int)
    sort = request_obj.args.get("sort", default_sort, type=str)
    order = request_obj.args.get("order", "asc", type=str)
    search = request_obj.args.get("search", "", type=str)
    
    page, page_size = validate_pagination_params(page, page_size)
    
    return {
        "page": page,
        "page_size": page_size,
        "sort": sort,
        "order": order,
        "search": search
    }


def apply_sort(query, sort_field: Optional[str], order: str = "asc", sort_map: Optional[Dict[str, Any]] = None, default_field=None):
    """
    Apply sorting to a SQLAlchemy query.
    
    Args:
        query: SQLAlchemy query object
        sort_field: Field name to sort by
        order: Sort order (asc or desc)
        sort_map: Dictionary mapping field names to SQLAlchemy column objects
        default_field: Default field to use if sort_field not found
    
    Returns:
        Modified query with sorting applied
    """
    if not sort_field or not sort_map:
        return query
    
    sort_column = sort_map.get(sort_field, sort_map.get("id") if default_field is None else default_field)
    if sort_column is None:
        return query
    
    if order.lower() == "desc":
        return query.order_by(sort_column.desc())
    else:
        return query.order_by(sort_column.asc())


def apply_text_search(query, search_query: str, searchable_fields: List[Any]):
    """
    Apply text search to a SQLAlchemy query.
    
    Args:
        query: SQLAlchemy query object
        search_query: Search string
        searchable_fields: List of SQLAlchemy column objects to search in
    
    Returns:
        Modified query with search filter applied
    """
    if not search_query or not searchable_fields:
        return query
    
    from sqlalchemy import or_
    search_term = f"%{search_query}%"
    conditions = []
    
    for field in searchable_fields:
        try:
            conditions.append(field.ilike(search_term))
        except (AttributeError, TypeError):
            # Field is not a SQLAlchemy column, skip it
            pass
    
    if conditions:
        return query.filter(or_(*conditions))
    
    return query


def to_iso(dt) -> Optional[str]:
    """
    Convert datetime to ISO 8601 format string.
    
    Args:
        dt: Datetime object or None
    
    Returns:
        ISO 8601 formatted string or None
    """
    if dt is None:
        return None
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)
