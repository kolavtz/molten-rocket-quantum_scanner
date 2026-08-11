# API-First Dashboard Integration Guide

## Overview

This guide explains how to integrate the complete API-first architecture with your existing QuantumShield Flask application.

## Files Created

### Backend (Python/Flask)

1. **API Blueprints** (in `web/blueprints/`):
   - `api_home.py` - Home dashboard metrics endpoint
   - `api_assets.py` - Asset inventory and discovery endpoints
   - `api_cbom.py` - CBOM metrics and entries endpoints
   - `api_pqc.py` - PQC posture metrics and assets endpoints
   - `api_cyber.py` - Cyber rating endpoint
   - `api_reports.py` - Reports endpoints
   - `api_admin.py` - Admin endpoints (API key management)
   - `api_docs.py` - API documentation endpoints
   - `api_blueprint_init.py` - Blueprint registration helper

2. **Utilities** (in `utils/`):
   - `api_helper.py` - Pagination, response formatting, filtering helpers

3. **Authentication** (in `api/` or `middleware/`):
   - `api_auth.py` - API key validation, rate limiting, auth decorators

### Frontend (JavaScript/CSS)

1. **JavaScript** (in `web/static/js/`):
   - `api_client.js` - Universal API client with caching
   - `universal_table.js` - Reusable table component with sorting/pagination

2. **CSS** (in `web/static/css/`):
   - `api_dashboards.css` - Glassmorphism design system

3. **Templates** (in `web/templates/`):
   - `assets_api.html` - Example API-driven assets page

## Integration Steps

### Step 1: Register Blueprints in Your Flask App

In your `web/app.py`, add this in the Flask initialization section:

```python
# After creating Flask app and before running
from web.blueprints.api_blueprint_init import register_api_blueprints

# Register all API blueprints
register_api_blueprints(app)
```

### Step 2: Include API Helper in Requirements

Ensure your `requirements.txt` has:
```
Flask>=2.0
SQLAlchemy>=1.4
Flask-Login>=0.6
```

### Step 3: Create API Key Migration (Optional but Recommended)

If using Alembic or SQLAlchemy migrations, create the api_keys table:

```sql
CREATE TABLE api_keys (
    key VARCHAR(128) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    user_id VARCHAR(36),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at DATETIME,
    INDEX idx_is_active (is_active),
    INDEX idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

Or use Python:

```python
from src.db import engine
from middleware.api_auth import APIKey
from src.models import Base

# Create table
APIKey.__table__.create(engine, checkfirst=True)
```

### Step 4: Include CSS and JS in Base Template

In your `web/templates/base.html`, add in the `<head>`:

```html
<link rel="stylesheet" href="{{ url_for('static', filename='css/api_dashboards.css') }}">
<script src="{{ url_for('static', filename='js/api_client.js') }}"></script>
<script src="{{ url_for('static', filename='js/universal_table.js') }}"></script>
```

### Step 5: Update Your Dashboard Templates

Replace direct database queries with API calls. Example:

**OLD WAY (direct query):**
```python
@app.route('/assets')
def assets_list():
    assets = db.query(Asset).all()
    return render_template('assets.html', assets=assets)
```

**NEW WAY (API-driven):**
```python
@app.route('/assets')
@login_required
def assets_list():
    return render_template('assets_api.html')
```

Then in the template, the JavaScript handles all data fetching:
```html
<script>
  const table = new UniversalTable({
    dataFetcher: async (params) => api.getAssets(params),
    // ... configure columns
  });
  await table.init();
</script>
```

### Step 6: Test Individual Endpoints

Start your Flask app and test endpoints:

```bash
# Get home metrics
curl -X GET http://localhost:5000/api/home/metrics

# Get assets (paginated)
curl -X GET "http://localhost:5000/api/assets?page=1&page_size=25"

# Get discovery items
curl -X GET "http://localhost:5000/api/discovery?tab=domains"

# Get CBOM metrics
curl -X GET http://localhost:5000/api/cbom/metrics

# Get API documentation
curl -X GET http://localhost:5000/api/docs
```

## API Authentication

### Flask-Login Session (Default)

All endpoints require Flask-Login authentication. Users must be logged in via the web UI.

### API Key Authentication (Optional)

For programmatic access, create API keys:

```python
from middleware.api_auth import APIKey
from src.db import SessionLocal

db = SessionLocal()
new_key = APIKey.generate_key()
api_key = APIKey(
    key=new_key,
    name="My Integration Key",
    user_id=None,
    is_active=True
)
db.add(api_key)
db.commit()
print(f"New API Key: {new_key}")
```

Then use in requests:
```bash
curl -X GET http://localhost:5000/api/assets \
  -H "X-API-Key: sk_your_key_here"
```

## Response Format

ALL endpoints return this standardized format:

```json
{
  "success": true,
  "data": {
    "items": [...],           // For list endpoints
    "total": 150,             // Total record count
    "page": 1,                // Current page
    "page_size": 25,          // Records per page
    "total_pages": 6,         // Total pages
    "kpis": {...}             // Optional KPIs
  },
  "filters": {
    "sort": "field",
    "order": "asc",
    "search": "query"
  }
}
```

## Query Parameters

### Pagination
- `page` (int): Page number, default 1
- `page_size` (int): Records per page, default 25, max 100

### Sorting
- `sort` (string): Field to sort by
- `order` (string): "asc" or "desc", default "asc"

### Search
- `q` (string): Search query (full-text on searchable fields)

### Examples
```
GET /api/assets?page=1&page_size=50&sort=risk_level&order=desc
GET /api/discovery?tab=ssl&q=example.com
GET /api/cbom/entries?sort=key_length&order=asc
```

## Endpoint Reference

### Home Dashboard
- `GET /api/home/metrics` - Dashboard KPIs

### Asset Management
- `GET /api/assets` - Paginated assets list
- `GET /api/assets/{id}` - Asset details
- `GET /api/discovery?tab={domains|ssl|ips|software}` - Discovery items

### CBOM
- `GET /api/cbom/metrics` - CBOM KPIs
- `GET /api/cbom/entries` - Paginated CBOM entries
- `GET /api/cbom/summary?scan_id=123` - Scan summary

### PQC Posture
- `GET /api/pqc-posture/metrics` - Posture distribution
- `GET /api/pqc-posture/assets` - Assets with PQC scores

### Cyber Rating
- `GET /api/cyber-rating` - Current rating
- `GET /api/cyber-rating/history` - Rating history

### Reports
- `GET /api/reports/scheduled` - Scheduled reports
- `GET /api/reports/ondemand` - On-demand reports
- `GET /api/reports/{id}` - Report details

### Admin (Require Admin Role)
- `GET /api/admin/api-keys` - List API keys
- `POST /api/admin/api-keys` - Create API key
- `DELETE /api/admin/api-keys/{name}` - Revoke API key
- `GET /api/admin/metrics` - Admin dashboard
- `POST /api/admin/flush-cache` - Clear caches

### Documentation
- `GET /api/docs` - OpenAPI specification
- `GET /docs` - HTML documentation

## Caching

The JavaScript API client automatically caches GET requests for 1 minute:

```javascript
// Disable caching
const response = await api.fetch('/assets', { useCache: false });

// Clear all cache
api.clearCache();

// Clear specific endpoint cache
api.clearCache('assets');
```

## Error Handling

All errors return this format:

```json
{
  "success": false,
  "error": "Error message",
  "message": "Optional detailed message"
}
```

In JavaScript:

```javascript
try {
  const data = await api.getAssets();
  // Use data
} catch (error) {
  console.error('Failed:', error.message);
  // Show user-friendly error message
}
```

## Rate Limiting

Endpoints are rate-limited to 10 requests per second per IP address.

Rate limit exceeded returns HTTP 429:
```json
{
  "success": false,
  "error": "Rate limit exceeded: 10 requests per 1s"
}
```

## Frontend Table Integration

Use `UniversalTable` for any paginated data:

```javascript
const myTable = new UniversalTable({
  containerId: 'my-table-div',
  pageSize: 25,
  dataFetcher: async (params) => {
    return await api.fetch('/my-endpoint', {
      params: {
        page: params.page,
        page_size: params.pageSize,
        sort: params.sort,
        order: params.order
      }
    });
  },
  columns: [
    { field: 'id', label: 'ID' },
    { field: 'name', label: 'Name', sortable: true },
    { field: 'status', label: 'Status', sortable: true }
  ],
  formatters: {
    status: (value) => `<span class="badge">${value}</span>`
  },
  onRowClick: (row) => console.log('Clicked:', row)
});

await myTable.init();
```

## Troubleshooting

### 401 Unauthorized
- Ensure user is logged in (`@login_required` decorator)
- Check API key is valid and not expired
- Verify `X-API-Key` header is present

### 404 Not Found
- Check endpoint path spelling
- Verify resource ID exists
- Check query parameters

### 500 Server Error
- Check Flask app logs: `tail -f app.log`
- Verify database connection
- Check SQL queries for syntax errors

### Slow Responses
- Use pagination (`page_size=25`)
- Add filters/search to reduce result set
- Check database indexes on common sort fields

## Performance Tips

1. **Use pagination** - Always use `page_size` for large datasets
2. **Filter results** - Use search (`q=`) to reduce data
3. **Client-side caching** - API client caches by default
4. **Server-side indexes** - Ensure database indexes on common sort/filter fields
5. **Batch requests** - Combine related API calls where possible

## Next Steps

1. Test all endpoints with provided curl commands
2. Convert remaining templates to use API client
3. Remove old direct database query routes
4. Add API key management UI to admin panel
5. Implement additional endpoints as needed for custom features
6. Monitor API logs and performance metrics

## Support

For issues or questions:
1. Check API error messages in browser console
2. Review endpoint specification in `/api/docs`
3. Test endpoint with curl before using in JavaScript
4. Check Flask app logs for backend errors
