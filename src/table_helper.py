import math
from sqlalchemy import or_, desc, asc

def paginate_query(query, model, page: int, page_size: int, sort_field: str, sort_dir: str, search_term: str, searchable_columns: list):
    """
    Applies search, fast-sort sorting, and pagination offset against an SQLAlchemy unfulfilled query object.
    
    Args:
        query: Base SQLAlchemy ORM query (already filtered for is_deleted=False if applicable)
        model: The SQLAlchemy declarative model class
        page (int): Current page number (1-indexed)
        page_size (int): Items per page (10, 25, 50)
        sort_field (str): The column name to sort by
        sort_dir (str): 'asc' or 'desc'
        search_term (str): String query applied securely
        searchable_columns (list): List of Column attributes on `model` to search against using ILIKE or standard LIKE
        
    Returns:
        dict: {
            "items": list of queried objects (results for current page),
            "total_count": int, true row count factoring search but un-paginated,
            "page": int,
            "page_size": int,
            "total_pages": int
        }
    """
    # 1. Apply Full-text Search
    if search_term and searchable_columns:
        filter_exprs = [col.ilike(f"%{search_term}%") for col in searchable_columns]
        query = query.filter(or_(*filter_exprs))
        
    # 2. Get Total Hits
    # It is faster to use query.count() or func.count(model.id) to derive pagination thresholds
    total_count = query.count()
    
    # 3. Apply Ordering
    if sort_field and hasattr(model, sort_field):
        col = getattr(model, sort_field)
        if sort_dir.lower() == 'desc':
            query = query.order_by(desc(col))
        else:
            query = query.order_by(asc(col))
    else:
        # Default fallback
        if hasattr(model, 'id'):
            query = query.order_by(desc(model.id))
            
    # 4. Apply Limit / Offset
    total_pages = math.ceil(total_count / page_size) if total_count > 0 else 1
    if page < 1: page = 1
    if page > total_pages: page = total_pages
    
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    items = query.all()
    
    return {
        "items": items,
        "total_count": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }
