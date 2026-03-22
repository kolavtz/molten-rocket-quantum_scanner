"""
API Documentation - /api/docs and /docs endpoints
Provides API documentation and specification.
"""

from flask import Blueprint, request, jsonify, render_template_string
from flask_login import login_required
from utils.api_helper import api_response

api_docs = Blueprint("api_docs", __name__, url_prefix="/api")


API_ENDPOINTS_SPEC = {
    "version": "1.0.0",
    "title": "QuantumShield API",
    "description": "Complete API-first dashboard for quantum-safe cryptography assessment",
    "baseUrl": "/api",
    "endpoints": [
        {
            "path": "/home/metrics",
            "method": "GET",
            "description": "Dashboard KPIs (assets, scans, quantum-safe %, vulnerable count, avg PQC score)",
            "auth": "Flask-Login",
            "parameters": []
        },
        {
            "path": "/assets",
            "method": "GET",
            "description": "Paginated list of assets with sorting and search",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "page", "type": "integer", "default": 1},
                {"name": "page_size", "type": "integer", "default": 25},
                {"name": "sort", "type": "string", "enum": ["asset_name", "risk_level", "created_at", "updated_at"]},
                {"name": "order", "type": "string", "enum": ["asc", "desc"]},
                {"name": "q", "type": "string", "description": "Search query"}
            ]
        },
        {
            "path": "/assets/{id}",
            "method": "GET",
            "description": "Detailed information about a specific asset",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "id", "type": "integer", "in": "path"}
            ]
        },
        {
            "path": "/discovery",
            "method": "GET",
            "description": "Asset discovery items (domains, SSL certs, IPs, software)",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "tab", "type": "string", "enum": ["domains", "ssl", "ips", "software"], "required": True},
                {"name": "page", "type": "integer", "default": 1},
                {"name": "page_size", "type": "integer", "default": 25},
                {"name": "sort", "type": "string"},
                {"name": "order", "type": "string", "enum": ["asc", "desc"]}
            ]
        },
        {
            "path": "/cbom/metrics",
            "method": "GET",
            "description": "CBOM KPIs (total apps, sites, certs, weak crypto, issues)",
            "auth": "Flask-Login",
            "parameters": []
        },
        {
            "path": "/cbom/entries",
            "method": "GET",
            "description": "Paginated CBOM entries (cryptographic algorithms and configurations)",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "page", "type": "integer", "default": 1},
                {"name": "page_size", "type": "integer", "default": 25},
                {"name": "sort", "type": "string", "enum": ["key_length", "algorithm_name", "category", "nist_status"]},
                {"name": "order", "type": "string", "enum": ["asc", "desc"]}
            ]
        },
        {
            "path": "/cbom/summary",
            "method": "GET",
            "description": "Summary of CBOM entries for a specific scan",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "scan_id", "type": "integer", "required": True}
            ]
        },
        {
            "path": "/pqc-posture/metrics",
            "method": "GET",
            "description": "PQC posture distribution (Elite, Standard, Legacy, Critical percentages)",
            "auth": "Flask-Login",
            "parameters": []
        },
        {
            "path": "/pqc-posture/assets",
            "method": "GET",
            "description": "Assets with PQC classification and scores",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "page", "type": "integer", "default": 1},
                {"name": "page_size", "type": "integer", "default": 25},
                {"name": "sort", "type": "string", "enum": ["pqc_score", "asset_name", "tier"]},
                {"name": "order", "type": "string", "enum": ["asc", "desc"]}
            ]
        },
        {
            "path": "/cyber-rating",
            "method": "GET",
            "description": "Latest enterprise cyber rating (0-1000) with tier and component scores",
            "auth": "Flask-Login",
            "parameters": []
        },
        {
            "path": "/cyber-rating/history",
            "method": "GET",
            "description": "Paginated history of cyber ratings over time",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "page", "type": "integer", "default": 1},
                {"name": "page_size", "type": "integer", "default": 25}
            ]
        },
        {
            "path": "/reports/scheduled",
            "method": "GET",
            "description": "List of scheduled report configurations",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "page", "type": "integer", "default": 1},
                {"name": "page_size", "type": "integer", "default": 25}
            ]
        },
        {
            "path": "/reports/ondemand",
            "method": "GET",
            "description": "History of on-demand generated reports",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "page", "type": "integer", "default": 1},
                {"name": "page_size", "type": "integer", "default": 25},
                {"name": "sort", "type": "string"},
                {"name": "order", "type": "string", "enum": ["asc", "desc"]}
            ]
        },
        {
            "path": "/reports/{id}",
            "method": "GET",
            "description": "Detailed information about a specific report",
            "auth": "Flask-Login",
            "parameters": [
                {"name": "id", "type": "integer", "in": "path"}
            ]
        },
        {
            "path": "/admin/api-keys",
            "method": "GET",
            "description": "List all API keys (Admin only)",
            "auth": "Flask-Login + Admin Role",
            "parameters": []
        },
        {
            "path": "/admin/api-keys",
            "method": "POST",
            "description": "Create new API key (Admin only)",
            "auth": "Flask-Login + Admin Role",
            "parameters": [
                {"name": "name", "type": "string", "in": "body"},
                {"name": "expires_in_days", "type": "integer", "in": "body", "default": 365}
            ]
        },
        {
            "path": "/admin/metrics",
            "method": "GET",
            "description": "Admin dashboard metrics (Admin only)",
            "auth": "Flask-Login + Admin Role",
            "parameters": []
        },
        {
            "path": "/admin/flush-cache",
            "method": "POST",
            "description": "Clear application caches (Admin only)",
            "auth": "Flask-Login + Admin Role",
            "parameters": []
        }
    ]
}


@api_docs.route("/docs", methods=["GET"])
@login_required
def get_api_docs():
    """
    GET /api/docs
    Returns OpenAPI specification or simple endpoint list.
    """
    return jsonify(API_ENDPOINTS_SPEC), 200


DOCS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumShield API Documentation</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        header {
            text-align: center;
            margin-bottom: 50px;
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .subtitle {
            color: #94a3b8;
            font-size: 1.1em;
        }
        
        .endpoints {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }
        
        .endpoint-card {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.3s ease;
        }
        
        .endpoint-card:hover {
            border-color: rgba(96, 165, 250, 0.3);
            background: rgba(30, 41, 59, 0.8);
            transform: translateY(-2px);
        }
        
        .method {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .method.GET { background-color: #3b82f6; }
        .method.POST { background-color: #10b981; }
        .method.DELETE { background-color: #ef4444; }
        
        .path {
            font-family: 'Courier New', monospace;
            color: #60a5fa;
            word-break: break-all;
            margin-bottom: 8px;
        }
        
        .description {
            color: #cbd5e1;
            font-size: 0.95em;
            margin-bottom: 10px;
        }
        
        .auth {
            color: #fbbf24;
            font-size: 0.9em;
            padding: 8px;
            background: rgba(251, 191, 36, 0.1);
            border-radius: 4px;
            margin-top: 10px;
        }
        
        .response-format {
            background: rgba(0, 0, 0, 0.3);
            border-left: 3px solid #60a5fa;
            padding: 15px;
            border-radius: 4px;
            margin-top: 30px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #a5f3fc;
            overflow-x: auto;
        }
        
        code {
            background: rgba(0, 0, 0, 0.2);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        .footer {
            text-align: center;
            margin-top: 60px;
            padding-top: 40px;
            border-top: 1px solid rgba(148, 163, 184, 0.1);
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 QuantumShield API</h1>
            <p class="subtitle">Complete API-First Dashboard for Post-Quantum Cryptography Assessment</p>
        </header>
        
        <div class="endpoints">
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/home/metrics</div>
                <div class="description">Dashboard KPIs (assets, scans, quantum-safe %, vulnerable count)</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/assets</div>
                <div class="description">Paginated list of assets with sorting and search</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/discovery?tab=domains</div>
                <div class="description">Asset discovery items (domains, SSL, IPs, software)</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/cbom/metrics</div>
                <div class="description">CBOM KPIs (apps, sites, certs, weak crypto)</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/cbom/entries</div>
                <div class="description">Paginated CBOM entries (crypto algorithms)</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/pqc-posture/metrics</div>
                <div class="description">PQC posture distribution (Elite/Standard/Legacy/Critical %)</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/pqc-posture/assets</div>
                <div class="description">Assets with PQC classification and scores</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/cyber-rating</div>
                <div class="description">Enterprise cyber rating (0-1000) with tier and scores</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/reports/scheduled</div>
                <div class="description">Scheduled report configurations</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/reports/ondemand</div>
                <div class="description">History of on-demand generated reports</div>
                <div class="auth">Auth: Flask-Login</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/admin/api-keys</div>
                <div class="description">List all API keys (Admin only)</div>
                <div class="auth">Auth: Flask-Login + Admin</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method POST">POST</span>
                <div class="path">/api/admin/api-keys</div>
                <div class="description">Create new API key (Admin only)</div>
                <div class="auth">Auth: Flask-Login + Admin</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method GET">GET</span>
                <div class="path">/api/admin/metrics</div>
                <div class="description">Admin dashboard metrics (Admin only)</div>
                <div class="auth">Auth: Flask-Login + Admin</div>
            </div>
            
            <div class="endpoint-card">
                <span class="method POST">POST</span>
                <div class="path">/api/admin/flush-cache</div>
                <div class="description">Clear application caches (Admin only)</div>
                <div class="auth">Auth: Flask-Login + Admin</div>
            </div>
        </div>
        
        <div class="response-format">
            <strong>Standard Response Format:</strong><br><br>
            {<br>
            &nbsp;&nbsp;"success": true,<br>
            &nbsp;&nbsp;"data": {<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"items": [...],<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"total": 150,<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"page": 1,<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"page_size": 25,<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"total_pages": 6,<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"kpis": {...}<br>
            &nbsp;&nbsp;},<br>
            &nbsp;&nbsp;"filters": {<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"sort": "field",<br>
            &nbsp;&nbsp;&nbsp;&nbsp;"order": "asc"<br>
            &nbsp;&nbsp;}<br>
            }
        </div>
        
        <div class="footer">
            <p>QuantumShield API v1.0 | All endpoints require authentication</p>
        </div>
    </div>
</body>
</html>
"""


@api_docs.route("/../docs", methods=["GET"])
@login_required
def get_html_docs():
    """
    GET /docs
    Returns human-readable HTML documentation.
    """
    return DOCS_HTML, 200, {"Content-Type": "text/html"}
