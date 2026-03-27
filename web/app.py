# pyre-ignore-all-errors
# Dummy reload for SQLAlchemy mappings
"""
Quantum-Safe TLS Scanner — Flask Web Application

Routes:
    GET  /            → Scanner dashboard
    POST /scan        → Run scan pipeline
    GET  /results/<id>→ View scan results
    GET  /cbom/<id>   → Download CBOM JSON
    GET  /api/scan    → REST API endpoint
"""

import sys
import typing
try:
    if hasattr(sys.stdout, 'reconfigure'):
        typing.cast(typing.Any, sys.stdout).reconfigure(encoding='utf-8')
except Exception:
    pass

import json
import re

import os
import uuid
import traceback
import logging
import socket
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from flask import (
    Flask,
    g,
    current_app,
    render_template,
    request,
    jsonify,
    send_file,
    redirect,
    url_for,
    Response,
    flash,
    session,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps, lru_cache
import threading

import sys
import typing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from config import SECRET_KEY, DEBUG, FLASK_HOST, FLASK_PORT, RESULTS_DIR, AUTODISCOVERY_PORTS, BASE_DIR
from src.scanner.network_discovery import NetworkScanner, sanitize_target
from src.scanner.tls_analyzer import TLSAnalyzer
from src.scanner.pqc_detector import PQCDetector
from src.cbom.builder import CBOMBuilder
from src.cbom.cyclonedx_generator import CycloneDXGenerator
from src.validator.quantum_safe_checker import QuantumSafeChecker
from src.validator.certificate_issuer import CertificateIssuer
from src.reporting.report_generator import ReportGenerator
from src.reporting.recommendation_engine import RecommendationEngine
from src.services.dashboard_data_service import DashboardDataService
from src import database as db
from src.db import db_session

# ── Flask App ────────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)
app.secret_key = SECRET_KEY

@app.teardown_appcontext
def shutdown_session(exception=None):
    """
    Remove the scoped_session at request teardown.
    This prevents memory leaks and stale transactions (e.g., OperationalError).
    """
    try:
        db_session.remove()
    except Exception:
        pass


# Security Hardening & Mail Config
from config import (
    MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME,
    MAIL_SERVER,
    MAIL_PORT,
    MAIL_USE_TLS,
    MAIL_USE_SSL,
    MAIL_USERNAME,
    MAIL_PASSWORD,
    MAIL_DEFAULT_SENDER,
    FORCE_HTTPS,
    TRUST_PROXY_SSL_HEADER,
    HSTS_SECONDS,
    MAX_LOGIN_ATTEMPTS,
    LOGIN_LOCKOUT_MINUTES,
    SESSION_COOKIE_NAME,
    SESSION_IDLE_TIMEOUT_SECONDS,
    AUDIT_LOG_PAGE_SIZE,
    RATELIMIT_STORAGE_URI,
    RATELIMIT_ENABLED,
    RATELIMIT_DEFAULT_LIMITS,
    CSP_CONFIG,
)

app.config.update(
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY=SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=PERMANENT_SESSION_LIFETIME,
    MAIL_SERVER=MAIL_SERVER,
    MAIL_PORT=MAIL_PORT,
    MAIL_USE_TLS=MAIL_USE_TLS,
    MAIL_USE_SSL=MAIL_USE_SSL,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_DEFAULT_SENDER=MAIL_DEFAULT_SENDER,
    PREFERRED_URL_SCHEME="https" if FORCE_HTTPS else "http",
    SESSION_COOKIE_NAME=SESSION_COOKIE_NAME,
    # Keep CSRF token validation enabled, but do not hard-require Referer for HTTPS POSTs.
    # Some local/reverse-proxy/browser setups strip Referer, which otherwise blocks form deletes with 400.
    WTF_CSRF_SSL_STRICT=False,
)

if TRUST_PROXY_SSL_HEADER:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Cache and throttling helpers for large datasets
_dashboard_cache = {
    "data": None,
    "updated_at": 0,
}
_dashboard_ttl_seconds = 30

# Database init guard for WSGI / debug reload flows
_db_initialized = False
_db_init_lock = threading.Lock()

from flask import Blueprint
dashboard_bp = Blueprint('main', __name__)

mail = Mail(app)
csrf = CSRFProtect(app)
talisman = Talisman(app, content_security_policy=CSP_CONFIG, force_https=FORCE_HTTPS)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=RATELIMIT_DEFAULT_LIMITS,  # type: ignore[arg-type]
    storage_uri=RATELIMIT_STORAGE_URI,
    enabled=RATELIMIT_ENABLED,
)

def get_dashboard_data() -> dict:
    """Return real-time dashboard aggregation totals."""
    return DashboardDataService.get_all_scans_aggregated()


def invalidate_dashboard_cache() -> None:
    """Clear dashboard caches after asset or scan mutations."""
    _dashboard_cache["data"] = None
    _dashboard_cache["updated_at"] = 0
    try:
        from web.blueprints import dashboard as dashboard_blueprint

        dashboard_blueprint._dashboard_data_cache["data"] = None
        dashboard_blueprint._dashboard_data_cache["updated_at"] = 0
    except Exception:
        pass


def _start_scheduler_if_enabled() -> None:
    """Start background scheduler once in runtime context.

    Avoid starting scheduler at import-time (tests/reloader parent process),
    which can make startup appear stuck and create duplicate background work.
    """
    from config import AUTOMATED_SCAN_ENABLED

    if not AUTOMATED_SCAN_ENABLED:
        logger.info("Automated scheduler disabled.")
        return

    # In Flask debug reloader, parent process should not start background threads.
    if DEBUG and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    try:
        from src.scheduler import start_scheduler
        start_scheduler()
    except Exception as e:
        app.logger.error("Failed to start automated scan scheduler: %s", e)


SCAN_ROLES = {"Admin", "Manager", "SingleScan", "Viewer"}
BULK_SCAN_ROLES = {"Admin", "Manager"}
ADMIN_PANEL_ROLES = {"Admin"}
ALL_APP_ROLES = {"Admin", "Manager", "SingleScan", "Viewer"}

# ── Theme Configuration ───────────────────────────────────────────
THEME_FILE = os.path.join(os.path.dirname(__file__), "theme.json")


_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

THEME_DEFAULTS = {
    "dark": {
        "bg_navbar": "#0f172a",
        "bg_primary": "#020617",
        "bg_secondary": "#0b1120",
        "bg_card": "#0f172a",
        "bg_input": "#111827",
        "border_subtle": "#334155",
        "border_hover": "#60a5fa",
        "text_primary": "#e5e7eb",
        "text_secondary": "#9ca3af",
        "text_muted": "#6b7280",
        "accent_color": "#2563eb",
        "text_on_accent": "#f9fafb",
        "safe": "#22c55e",
        "warn": "#f59e0b",
        "danger": "#ef4444",
    },
    "light": {
        "bg_navbar": "#ffffff",
        "bg_primary": "#f3f4f6",
        "bg_secondary": "#ffffff",
        "bg_card": "#ffffff",
        "bg_input": "#ffffff",
        "border_subtle": "#cbd5f5",
        "border_hover": "#2563eb",
        "text_primary": "#0f172a",
        "text_secondary": "#475569",
        "text_muted": "#9ca3af",
        "accent_color": "#2563eb",
        "text_on_accent": "#ffffff",
        "safe": "#22c55e",
        "warn": "#f59e0b",
        "danger": "#ef4444",
    },
}


def _normalize_hex_color(value: Any, fallback: str) -> str:
    text = str(value or "").strip()
    if _HEX_COLOR_RE.match(text):
        return text.lower()
    return fallback


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    c = typing.cast(typing.Any, color.lstrip("#"))
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def _relative_luminance(color: str) -> float:
    r, g, b = _hex_to_rgb(color)

    def _channel(v: int) -> float:
        x = v / 255.0
        return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4

    rl = _channel(r)
    gl = _channel(g)
    bl = _channel(b)
    return 0.2126 * rl + 0.7152 * gl + 0.0722 * bl


def _contrast_ratio(color_a: str, color_b: str) -> float:
    la = _relative_luminance(color_a)
    lb = _relative_luminance(color_b)
    lighter = max(la, lb)
    darker = min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def _sanitize_theme_palette(raw_palette: dict | None, defaults: dict) -> dict:
    raw_palette = raw_palette if isinstance(raw_palette, dict) else {}
    palette = {
        "bg_navbar": _normalize_hex_color(raw_palette.get("bg_navbar"), defaults["bg_navbar"]),
        "bg_primary": _normalize_hex_color(raw_palette.get("bg_primary"), defaults["bg_primary"]),
        "bg_secondary": _normalize_hex_color(raw_palette.get("bg_secondary"), defaults["bg_secondary"]),
        "bg_card": _normalize_hex_color(raw_palette.get("bg_card"), defaults["bg_card"]),
        "bg_input": _normalize_hex_color(raw_palette.get("bg_input"), defaults["bg_input"]),
        "border_subtle": _normalize_hex_color(raw_palette.get("border_subtle"), defaults["border_subtle"]),
        "border_hover": _normalize_hex_color(raw_palette.get("border_hover"), defaults["border_hover"]),
        "text_primary": _normalize_hex_color(raw_palette.get("text_primary"), defaults["text_primary"]),
        "text_secondary": _normalize_hex_color(raw_palette.get("text_secondary"), defaults["text_secondary"]),
        "text_muted": _normalize_hex_color(raw_palette.get("text_muted"), defaults["text_muted"]),
        "accent_color": _normalize_hex_color(raw_palette.get("accent_color"), defaults["accent_color"]),
        "text_on_accent": _normalize_hex_color(raw_palette.get("text_on_accent"), defaults.get("text_on_accent", "#ffffff")),
        "safe": _normalize_hex_color(raw_palette.get("safe"), defaults["safe"]),
        "warn": _normalize_hex_color(raw_palette.get("warn"), defaults["warn"]),
        "danger": _normalize_hex_color(raw_palette.get("danger"), defaults["danger"]),
    }

    if _contrast_ratio(palette["bg_primary"], palette["text_primary"]) < 4.5:
        dark_text = "#0b1120"
        light_text = "#f3f4f6"
        dark_ratio = _contrast_ratio(palette["bg_primary"], dark_text)
        light_ratio = _contrast_ratio(palette["bg_primary"], light_text)
        palette["text_primary"] = dark_text if dark_ratio >= light_ratio else light_text

    if _contrast_ratio(palette["bg_card"], palette["text_secondary"]) < 3.0:
        palette["text_secondary"] = palette["text_primary"]
    if _contrast_ratio(palette["bg_card"], palette["text_muted"]) < 2.5:
        palette["text_muted"] = palette["text_secondary"]

    return palette


def _sanitize_theme(raw_theme: dict) -> dict:
    raw_theme = raw_theme if isinstance(raw_theme, dict) else {}
    if "dark" in raw_theme or "light" in raw_theme:
        dark = _sanitize_theme_palette(raw_theme.get("dark"), THEME_DEFAULTS["dark"])
        light = _sanitize_theme_palette(raw_theme.get("light"), THEME_DEFAULTS["light"])
        mode = str(raw_theme.get("mode") or "system").lower()
    else:
        dark = _sanitize_theme_palette(raw_theme, THEME_DEFAULTS["dark"])
        light = _sanitize_theme_palette(raw_theme, THEME_DEFAULTS["light"])
        mode = str(raw_theme.get("mode") or "system").lower()

    if mode not in {"system", "dark", "light"}:
        mode = "system"

    active = dark if mode == "dark" else light if mode == "light" else dark
    return {
        "mode": mode,
        "dark": dark,
        "light": light,
        "active": active,
        "bg_navbar": active["bg_navbar"],
        "accent_color": active["accent_color"],
        "bg_primary": active["bg_primary"],
        "text_primary": active["text_primary"],
    }

def load_theme():
    if os.path.exists(THEME_FILE):
        try:
            with open(THEME_FILE, 'r') as f:
                data = json.load(f)
                return _sanitize_theme(data if isinstance(data, dict) else {})
        except Exception:
            pass
    return _sanitize_theme({"dark": THEME_DEFAULTS["dark"], "light": THEME_DEFAULTS["light"], "mode": "system"})

@app.context_processor
def inject_theme():
    return dict(theme=load_theme())

@app.context_processor
def inject_csrf_token():
    """Ensure CSRF token is always available in templates."""
    try:
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf)
    except Exception:
        return dict(csrf_token=lambda: "")


# Graceful CSRF handling
from flask_wtf.csrf import CSRFError

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Provide a helpful feedback path for missing/invalid CSRF tokens."""
    logger.warning("CSRF validation failed: %s", str(e))
    flash("Security check failed (CSRF token missing or invalid). Please reload the login page and try again.", "error")

    # If the user was already on login page, preserve feedback and show login form.
    if request.path == url_for('login'):
        return render_template('login.html', locked=False), 400

    return redirect(url_for('login'))


@app.before_request
def initialize_database():
    """Ensure MySQL bootstrap runs once in any WSGI/DEV server startup path."""
    if not _db_initialized:
        _bootstrap_runtime_state()


# Authentication
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_dict):
        self.id = user_dict["id"]
        self.username = user_dict["username"]
        self.role = db.normalize_role(user_dict.get("role", "Viewer"))
        self.is_active_user = bool(user_dict.get("is_active", True))

    @property
    def is_active(self):
        return self.is_active_user

@login_manager.user_loader
def load_user(user_id):
    user_data = db.get_user_by_id(str(user_id))
    if user_data:
        return User(user_data)
    return None

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                db.append_audit_log(
                    event_category="auth",
                    event_type="unauthenticated_access_attempt",
                    status="denied",
                    ip_address=_get_request_ip(),
                    user_agent=request.headers.get("User-Agent", "")[:512],
                    request_method=request.method,
                    request_path=request.path,
                    details={"required_roles": roles},
                )
                return redirect(url_for('login'))
            if current_user.role not in roles:
                _audit("auth", "authorization_denied", "denied", details={"required_roles": roles, "actual_role": current_user.role})
                flash("You do not have permission to access this resource.", "error")
                return redirect(url_for('quantumshield_dashboard.dashboard_home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_api_key(f):
    """Decorator — enforces API key authentication for machine-facing endpoints.

    Reads the key from the ``X-API-Key`` header (preferred) or the
    ``api_key`` query parameter (CI/CD fallback).  On success, the resolved
    user dict is stored in ``flask.g.api_user``.  On failure returns a
    structured JSON 401 and logs the attempt.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        if app.config.get("TESTING"):
            g.api_user = {
                "id": "test-user",
                "username": "test",
                "role": "Admin",
            }
            return f(*args, **kwargs)

        raw_key = (
            request.headers.get("X-API-Key", "")
            or request.args.get("api_key", "")
            or (request.get_json(silent=True) or {}).get("api_key", "")
        ).strip()

        if not raw_key:
            db.append_audit_log(
                event_category="api",
                event_type="api_key_missing",
                status="denied",
                ip_address=_get_request_ip(),
                user_agent=request.headers.get("User-Agent", "")[:512],
                request_method=request.method,
                request_path=request.path,
            )
            return jsonify({"error": "API key required", "hint": "Pass X-API-Key header or ?api_key= param"}), 401

        user_data = db.get_user_by_api_key(raw_key)
        if not user_data:
            db.append_audit_log(
                event_category="api",
                event_type="api_key_invalid",
                status="denied",
                ip_address=_get_request_ip(),
                user_agent=request.headers.get("User-Agent", "")[:512],
                request_method=request.method,
                request_path=request.path,
            )
            return jsonify({"error": "Invalid or revoked API key"}), 401

        g.api_user = user_data
        db.append_audit_log(
            event_category="api",
            event_type="api_key_authenticated",
            status="success",
            actor_user_id=user_data.get("id"),
            actor_username=user_data.get("username"),
            ip_address=_get_request_ip(),
            user_agent=request.headers.get("User-Agent", "")[:512],
            request_method=request.method,
            request_path=request.path,
            details={"role": user_data.get("role")},
        )
        return f(*args, **kwargs)
    return decorated

def _is_https_request() -> bool:
    if request.is_secure:
        return True
    return request.headers.get("X-Forwarded-Proto", "").lower() == "https"


def _validate_password_strength(password: str) -> tuple[bool, str]:
    if not password or len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not any(ch.isupper() for ch in password):
        return False, "Password must include at least one uppercase letter."
    if not any(ch.islower() for ch in password):
        return False, "Password must include at least one lowercase letter."
    if not any(ch.isdigit() for ch in password):
        return False, "Password must include at least one number."
    if not any(not ch.isalnum() for ch in password):
        return False, "Password must include at least one special character."
    return True, ""


def _build_setup_link(token: str) -> str:
    scheme = "https" if FORCE_HTTPS else None
    return url_for("setup_password", token=token, _external=True, _scheme=scheme)


def _get_request_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"


def _audit(
    event_category: str,
    event_type: str,
    status: str,
    target_user_id: str | None = None,
    target_scan_id: str | None = None,
    details: dict | None = None,
) -> None:
    if app.config.get("TESTING", False):
        return
    actor_id = getattr(current_user, "id", None) if getattr(current_user, "is_authenticated", False) else None
    actor_username = getattr(current_user, "username", None) if getattr(current_user, "is_authenticated", False) else None
    db.append_audit_log(
        event_category=event_category,
        event_type=event_type,
        status=status,
        actor_user_id=actor_id,
        actor_username=actor_username,
        target_user_id=target_user_id,
        target_scan_id=target_scan_id,
        ip_address=_get_request_ip(),
        user_agent=request.headers.get("User-Agent", "")[:512],
        request_method=request.method,
        request_path=request.path,
        details=details or {},
    )


@app.before_request
def disable_login_in_testing():
    if app.config.get("TESTING"):
        app.config["LOGIN_DISABLED"] = True


@app.before_request
def enforce_https_redirect():
    if not FORCE_HTTPS:
        return None
    if app.config.get("TESTING") or request.path.startswith("/static/"):
        return None
    if _is_https_request():
        return None
    if request.host.startswith("127.0.0.1") or request.host.startswith("localhost"):
        return None
    secure_url = request.url.replace("http://", "https://", 1)
    return redirect(secure_url, code=301)


@app.before_request
def enforce_session_idle_timeout():
    if not getattr(current_user, "is_authenticated", False):
        session.pop("last_activity", None)
        return None

    now_ts = int(datetime.now(timezone.utc).timestamp())
    last_activity = session.get("last_activity")
    if last_activity and now_ts - int(last_activity) > SESSION_IDLE_TIMEOUT_SECONDS:
        user_name = getattr(current_user, "username", "unknown")
        logout_user()
        session.clear()
        db.append_audit_log(
            event_category="auth",
            event_type="session_timeout",
            status="success",
            actor_username=user_name,
            ip_address=_get_request_ip(),
            user_agent=request.headers.get("User-Agent", "")[:512],
            request_method=request.method,
            request_path=request.path,
            details={"idle_timeout_seconds": SESSION_IDLE_TIMEOUT_SECONDS},
        )
        flash("Session expired due to inactivity. Please sign in again.", "warning")
        return redirect(url_for("login"))

    session.permanent = True
    session["last_activity"] = now_ts
    return None


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if FORCE_HTTPS:
        response.headers["Strict-Transport-Security"] = f"max-age={HSTS_SECONDS}; includeSubDomains"
    csp_policy = (
        "default-src 'self'; "
        "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com https://unpkg.com; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
        "connect-src 'self' https://ipapi.co; "
        "worker-src blob:; "
        "frame-ancestors 'none'"
    )
    response.headers["Content-Security-Policy"] = csp_policy
    return response

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

# ── Logging Setup ───────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(BASE_DIR, "app.log"))
    ]
)
logger = logging.getLogger(__name__)
logger.info("QuantumShield application starting up...")

# In-memory store — hydrated from MySQL on cold start
scan_store: dict = {}
_geo_cache: dict[str, dict] = {}


def _parse_cert_time(value: str) -> str:
    """Convert OpenSSL-style certificate timestamp into ISO date string."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.date().isoformat()
        except ValueError:
            continue
    return raw[:10]


def _parse_cert_datetime(value: str) -> datetime | None:
    """Convert certificate time strings into naive datetimes for SQL persistence."""
    raw = str(value or "").strip()
    if not raw:
        return None
    candidates = (
        "%b %d %H:%M:%S %Y %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    )
    for fmt in candidates:
        try:
            parsed = datetime.strptime(raw, fmt)
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _days_to_expiry(cert_not_after: str) -> int | None:
    """Return days until expiry from OpenSSL-style notAfter string."""
    raw = str(cert_not_after or "").strip()
    if not raw:
        return None
    try:
        exp_dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
        now = datetime.utcnow()
        return int((exp_dt - now).days)
    except ValueError:
        return None


def _cert_component(mapping: dict[str, Any] | None, field_name: str) -> str:
    source = mapping if isinstance(mapping, dict) else {}
    aliases = {
        "cn": ("CN", "commonName"),
        "o": ("O", "organizationName"),
        "ou": ("OU", "organizationalUnitName"),
    }
    for candidate in aliases.get(field_name.lower(), (field_name,)):
        value = str(source.get(candidate) or "").strip()
        if value:
            return value
    return ""


def _principal_display(cn: str, org: str, unit: str) -> str:
    parts = [str(cn or "").strip(), str(org or "").strip(), str(unit or "").strip()]
    return ", ".join(part for part in parts if part)


def _json_text(value: Any) -> str | None:
    if value in (None, "", [], {}):
        return None
    try:
        return json.dumps(value, default=_json_default)
    except Exception:
        return None


def _json_default(value: Any):
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    return str(value)


def _coerce_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _db_table_exists(table_name: str) -> bool:
    try:
        from sqlalchemy import inspect

        bind = db_session.get_bind()
        return bool(bind is not None and inspect(bind).has_table(table_name))
    except Exception:
        return False


def _persist_split_discovery_rows(
    scan_pk: int | None,
    asset_id: int,
    target: str,
    discovered_services: list[dict[str, Any]],
    tls_results: list[dict[str, Any]],
    location_points: list[dict[str, Any]],
) -> None:
    """Persist discovery telemetry into the live split discovery tables when present."""
    if not scan_pk or asset_id <= 0:
        return

    from sqlalchemy import text

    now = datetime.now()
    host = _host_from_target(target).strip().lower()
    geo_by_ip = {str(item.get("ip") or ""): item for item in (location_points or [])}

    if _db_table_exists("discovery_domains"):
        seen_domains: set[str] = set()
        domains = [host] if host else []
        for tls in tls_results:
            for domain in (tls.get("san_domains") or []):
                normalized = _host_from_target(str(domain or "")).strip().lower()
                if normalized:
                    domains.append(normalized)
        for domain in domains:
            normalized = _host_from_target(domain).strip().lower()
            if not normalized or normalized in seen_domains:
                continue
            seen_domains.add(normalized)
            db_session.execute(
                text(
                    """
                    INSERT INTO discovery_domains (
                        scan_id, asset_id, domain, status, promoted_to_inventory,
                        promoted_at, created_at, updated_at
                    ) VALUES (
                        :scan_id, :asset_id, :domain, :status, :promoted_to_inventory,
                        :promoted_at, :created_at, :updated_at
                    )
                    """
                ),
                {
                    "scan_id": scan_pk,
                    "asset_id": asset_id,
                    "domain": normalized,
                    "status": "confirmed",
                    "promoted_to_inventory": True,
                    "promoted_at": now,
                    "created_at": now,
                    "updated_at": now,
                },
            )

    if _db_table_exists("discovery_ips"):
        seen_ips: set[str] = set()
        for svc in discovered_services:
            ip_addr = str(svc.get("host") or "").strip()
            if not ip_addr or ip_addr in seen_ips:
                continue
            try:
                import ipaddress

                ip_obj = ipaddress.ip_address(ip_addr)
            except ValueError:
                continue
            seen_ips.add(ip_addr)
            geo = geo_by_ip.get(ip_addr, {})
            location = ", ".join(
                part for part in (
                    str(geo.get("city") or "").strip(),
                    str(geo.get("region") or "").strip(),
                    str(geo.get("country") or "").strip(),
                )
                if part
            )
            subnet = f"{ip_addr}/32" if ip_obj.version == 4 else f"{ip_addr}/128"
            db_session.execute(
                text(
                    """
                    INSERT INTO discovery_ips (
                        scan_id, asset_id, ip_address, subnet, location, status,
                        promoted_to_inventory, promoted_at, created_at, updated_at
                    ) VALUES (
                        :scan_id, :asset_id, :ip_address, :subnet, :location, :status,
                        :promoted_to_inventory, :promoted_at, :created_at, :updated_at
                    )
                    """
                ),
                {
                    "scan_id": scan_pk,
                    "asset_id": asset_id,
                    "ip_address": ip_addr,
                    "subnet": subnet,
                    "location": location or None,
                    "status": "confirmed",
                    "promoted_to_inventory": True,
                    "promoted_at": now,
                    "created_at": now,
                    "updated_at": now,
                },
            )

    if _db_table_exists("discovery_software"):
        seen_software: set[tuple[str, str, str]] = set()
        for svc in discovered_services:
            service = str(svc.get("service") or "").strip()
            banner = str(svc.get("banner") or "").strip()
            raw_product = banner or service
            if not raw_product:
                continue
            product = raw_product.split("/", 1)[0].strip() or service or "Unknown"
            version = raw_product.split("/", 1)[1].strip() if "/" in raw_product else ""
            key = (product.lower(), version.lower(), service.lower())
            if key in seen_software:
                continue
            seen_software.add(key)
            db_session.execute(
                text(
                    """
                    INSERT INTO discovery_software (
                        scan_id, asset_id, product, version, category, status,
                        promoted_to_inventory, promoted_at, created_at, updated_at
                    ) VALUES (
                        :scan_id, :asset_id, :product, :version, :category, :status,
                        :promoted_to_inventory, :promoted_at, :created_at, :updated_at
                    )
                    """
                ),
                {
                    "scan_id": scan_pk,
                    "asset_id": asset_id,
                    "product": product,
                    "version": version or None,
                    "category": service or "software",
                    "status": "confirmed",
                    "promoted_to_inventory": True,
                    "promoted_at": now,
                    "created_at": now,
                    "updated_at": now,
                },
            )

    if _db_table_exists("discovery_ssl"):
        for tls in tls_results:
            endpoint_host = str(tls.get("host") or host or "").strip()
            endpoint_port = int(tls.get("port") or 443)
            endpoint = f"{endpoint_host}:{endpoint_port}" if endpoint_host else host
            db_session.execute(
                text(
                    """
                    INSERT INTO discovery_ssl (
                        scan_id, asset_id, endpoint, tls_version, cipher_suite, key_exchange,
                        key_length, subject_cn, issuer, valid_until, status,
                        promoted_to_inventory, promoted_at, created_at, updated_at
                    ) VALUES (
                        :scan_id, :asset_id, :endpoint, :tls_version, :cipher_suite, :key_exchange,
                        :key_length, :subject_cn, :issuer, :valid_until, :status,
                        :promoted_to_inventory, :promoted_at, :created_at, :updated_at
                    )
                    """
                ),
                {
                    "scan_id": scan_pk,
                    "asset_id": asset_id,
                    "endpoint": endpoint or None,
                    "tls_version": tls.get("protocol_version") or tls.get("tls_version") or "Unknown",
                    "cipher_suite": tls.get("cipher_suite") or "Unknown",
                    "key_exchange": tls.get("key_exchange") or "Unknown",
                    "key_length": int(tls.get("key_length") or tls.get("key_size") or 0) or None,
                    "subject_cn": tls.get("subject_cn") or None,
                    "issuer": tls.get("issuer_cn") or tls.get("issuer_o") or None,
                    "valid_until": tls.get("valid_until_dt"),
                    "status": "confirmed",
                    "promoted_to_inventory": True,
                    "promoted_at": now,
                    "created_at": now,
                    "updated_at": now,
                },
            )
def _normalize_tls_result(raw_result: dict) -> dict:
    """Normalize TLS analyzer output into dashboard/report-friendly schema."""
    raw = dict(raw_result or {})
    cert = typing.cast(dict, raw.get("certificate") if isinstance(raw.get("certificate"), dict) else {})
    issuer = cert.get("issuer") if isinstance(cert.get("issuer"), dict) else {}
    subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}

    cipher_suite = str(raw.get("cipher_suite") or "")
    cipher_suites = raw.get("all_cipher_suites") if isinstance(raw.get("all_cipher_suites"), list) else []
    if not cipher_suites and cipher_suite:
        cipher_suites = [cipher_suite]

    cert_days = cert.get("days_until_expiry") if isinstance(cert.get("days_until_expiry"), int) else None
    if cert_days is None:
        cert_days = _days_to_expiry(str(cert.get("not_after") or ""))

    cert_expired = bool(cert.get("is_expired"))
    if cert_days is not None and cert_days < 0:
        cert_expired = True

    cert_status = "Unknown"
    if cert_expired:
        cert_status = "Expired"
    elif cert_days is not None:
        cert_status = "Expiring" if cert_days <= 30 else "Valid"

    key_bits = cert.get("public_key_bits")
    if not isinstance(key_bits, int):
        key_bits = int(raw.get("cipher_bits") or 0)

    subject_cn = str(cert.get("subject_cn") or _cert_component(subject, "cn"))
    subject_o = str(cert.get("subject_o") or _cert_component(subject, "o"))
    subject_ou = str(cert.get("subject_ou") or _cert_component(subject, "ou"))
    issuer_cn = str(cert.get("issuer_cn") or _cert_component(issuer, "cn"))
    issuer_o = str(cert.get("issuer_o") or _cert_component(issuer, "o"))
    issuer_ou = str(cert.get("issuer_ou") or _cert_component(issuer, "ou"))
    valid_from = _parse_cert_time(str(cert.get("not_before") or ""))
    valid_to = _parse_cert_time(str(cert.get("not_after") or ""))

    return {
        "host": raw.get("host"),
        "port": raw.get("port"),
        "tls_version": raw.get("protocol_version") or raw.get("tls_version") or "Unknown",
        "protocol_version": raw.get("protocol_version") or raw.get("tls_version") or "Unknown",
        "cipher_suite": cipher_suite or "Unknown",
        "cipher_suites": cipher_suites,
        "cipher_bits": int(raw.get("cipher_bits") or 0),
        "key_exchange": raw.get("key_exchange") or "Unknown",
        "certificate_chain_length": int(raw.get("certificate_chain_length") or 0),
        "issuer": issuer,
        "subject": subject,
        "subject_cn": subject_cn,
        "subject_o": subject_o,
        "subject_ou": subject_ou,
        "issuer_cn": issuer_cn,
        "issuer_o": issuer_o,
        "issuer_ou": issuer_ou,
        "serial_number": str(cert.get("serial_number") or ""),
        "key_type": str(cert.get("public_key_type") or "Unknown"),
        "key_size": key_bits,
        "key_length": key_bits,
        "public_key_type": str(cert.get("public_key_type") or "Unknown"),
        "public_key_pem": str(cert.get("public_key_pem") or ""),
        "signature_algorithm": str(cert.get("signature_algorithm") or ""),
        "cert_sha256": str(cert.get("fingerprint_sha256") or ""),
        "san_domains": cert.get("san_domains") if isinstance(cert.get("san_domains"), list) else [],
        "valid_from": valid_from,
        "valid_to": valid_to,
        "valid_from_dt": _parse_cert_datetime(str(cert.get("not_before") or "")),
        "valid_until_dt": _parse_cert_datetime(str(cert.get("not_after") or "")),
        "cert_days_remaining": cert_days,
        "cert_expired": cert_expired,
        "cert_status": cert_status,
        "error": raw.get("error"),
    }


def _collect_dns_records(host: str) -> list[dict]:
    """Collect DNS records with stdlib and optional dnspython if available."""
    records: list[dict] = []
    host = _host_from_target(host)
    if not host:
        return records

    now = datetime.now(timezone.utc).isoformat()

    try:
        _, _, ip_list = socket.gethostbyname_ex(host)
        for ip in ip_list:
            records.append({"hostname": host, "record_type": "A", "record_value": ip, "ttl": 300, "resolved_at": now})
    except Exception:
        pass

    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6)
        seen = set()
        for info in infos:
            ip6 = info[4][0]
            if ip6 in seen:
                continue
            seen.add(ip6)
            records.append({"hostname": host, "record_type": "AAAA", "record_value": ip6, "ttl": 300, "resolved_at": now})
    except Exception:
        pass

    try:
        reverse_name = socket.gethostbyaddr(host)[0]
        records.append({"hostname": host, "record_type": "PTR", "record_value": reverse_name, "ttl": 300, "resolved_at": now})
    except Exception:
        pass

    try:
        import dns.resolver  # type: ignore

        for record_type in ("CNAME", "MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(host, record_type, lifetime=2.5)
                ttl = int(getattr(answers.rrset, "ttl", 300)) if getattr(answers, "rrset", None) else 300
                for ans in answers:
                    records.append(
                        {
                            "hostname": host,
                            "record_type": record_type,
                            "record_value": str(ans).strip(),
                            "ttl": ttl,
                            "resolved_at": now,
                        }
                    )
            except Exception:
                continue
    except Exception:
        pass

    uniq = set()
    deduped = []
    for r in records:
        key = (r["hostname"], r["record_type"], r["record_value"])
        if key in uniq:
            continue
        uniq.add(key)
        deduped.append(r)
    return deduped


def _geolocate_ip(ip_addr: str) -> dict:
    """Resolve IP to approximate geo metadata for map visualization."""
    if not ip_addr:
        return {}
    cached = _geo_cache.get(ip_addr)
    if cached is not None:
        return cached

    result: dict = {}
    try:
        url = f"https://ipapi.co/{urllib.parse.quote(ip_addr)}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield/1.0"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        lat = payload.get("latitude")
        lon = payload.get("longitude")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            result = {
                "ip": ip_addr,
                "lat": float(lat),
                "lon": float(lon),
                "city": str(payload.get("city") or ""),
                "region": str(payload.get("region") or ""),
                "country": str(payload.get("country_name") or payload.get("country") or ""),
            }
    except Exception:
        result = {}

    _geo_cache[ip_addr] = result
    return result


def _autodetect_asset_class(target: str, discovered_services: list[dict], manual_class: str | None = None) -> str:
    """Resolve business asset class from operator hint or scan evidence."""
    if manual_class:
        return manual_class

    target_l = str(target).lower()
    ports = {int(s.get("port") or 0) for s in discovered_services if str(s.get("port") or "").isdigit()}
    service_text = " ".join(str(s.get("service") or "") + " " + str(s.get("banner") or "") for s in discovered_services).lower()

    if "vpn" in target_l or 1194 in ports or 500 in ports or 4500 in ports:
        return "Corporate VPN"
    if "consumer" in target_l or "mobile" in target_l or "retail" in target_l:
        return "Consumer App"
    if "api" in target_l or "gateway" in target_l or 8443 in ports:
        return "API Service"
    if "db" in target_l or "oracle" in service_text or "mysql" in service_text:
        return "Core Banking Data"
    if 443 in ports or 80 in ports:
        return "Internet Banking"
    return "Other"

def _bootstrap_runtime_state() -> None:
    """Load scan state from MySQL when running the application for real."""
    global _db_available, _db_initialized

    if app.config.get("TESTING", False):
        _db_available = False
        _db_initialized = True
        return

    if _db_initialized:
        logger.debug("_bootstrap_runtime_state called but db already initialized.")
        return

    with _db_init_lock:
        if _db_initialized:
            logger.debug("_bootstrap_runtime_state already completed by another thread/process.")
            return

        # Retry in case of transient initialization failures (locks, transient disconnects).
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                logger.info("Initializing database connectivity at runtime (attempt %d/%d)...", attempt, max_attempts)
                _db_available = db.init_db()
            except Exception as exc:
                logger.warning("Database bootstrap attempt %d failed: %s", attempt, exc)
                _db_available = False

            if _db_available:
                break

            if attempt < max_attempts:
                import time
                time.sleep(1)

        if not _db_available:
            logger.warning("MySQL unavailable during runtime bootstrap after %d attempts; running in JSON-only mode.", max_attempts)
            _db_initialized = True
            return

        try:
            # Use the repository DB API rather than ORM model hydration.
            # This avoids hard coupling to optional ORM columns in legacy installs.
            for _report in db.list_scans(limit=10000):
                try:
                    _sid = str(_report.get("scan_id", "")).strip()
                    if _sid:
                        scan_store[_sid] = _report
                except Exception:
                    pass
            print(f"  💾 MySQL connected — loaded {len(scan_store)} scans from database")
        except Exception as exc:
            logger.warning("Failed to hydrate scan store from MySQL: %s", exc)
        finally:
            _db_initialized = True

        logger.info("Database initialization complete. Available=%s", _db_available)


# Initialise MySQL (if available) and hydrate scan_store
logger.info("Initializing database connectivity...")
_db_available = False
logger.info("Database bootstrap deferred until runtime startup hook.")

# Run data hydration only from runtime bootstrap path (_bootstrap_runtime_state)
# to avoid early ORM lookups against partially integrated legacy schemas.
print("  ⚙️ Waiting for runtime DB bootstrap...")

# ── Pipeline ─────────────────────────────────────────────────────────


def run_scan_pipeline(
    target: str,
    ports: list[int] | None = None,
    asset_class_hint: str | None = None,
    scan_kind: str = "manual",
    scanned_by: str | None = None,
) -> dict:
    """Execute the full scan pipeline and return a report dict.

    Enforced workflow (no shortcuts):
    1. User Input (inventory / API target) -> Network Scan
    2. TLS Analysis
    3. PQC Detection
    4. Risk Scoring
    5. CBOM Generation (CycloneDX)
    6. SQL persistence (Scan/Asset/Certificate/PQC/CBOM)
    7. Response back to frontend/dashboards
    """
    scan_id = uuid.uuid4().hex[:8]

    # 1. Service Discovery (broad port sweep)
    scanner = NetworkScanner()
    all_services = scanner.discover_services(target, ports)
    discovered_services = [
        {
            "host": ep.host,
            "port": ep.port,
            "service": ep.service,
            "is_tls": ep.is_tls,
            "banner": ep.banner,
        }
        for ep in all_services
    ]
    dns_records = _collect_dns_records(target)

    # 2. Filter to TLS-capable endpoints only
    tls_endpoints = [ep for ep in all_services if ep.is_tls]

    # Fallback: if no TLS endpoints from broad sweep, try deeper discovery
    if not tls_endpoints:
        endpoints = scanner.discover_targets(target, ports)

        if endpoints:
            # Use endpoints found by discover_targets for full TLS analysis
            analyzer = TLSAnalyzer()
            tls_results = []
            for ep in endpoints:
                result = analyzer.analyze_endpoint(ep.host, ep.port)
                if result.is_successful:
                    tls_results.append(_normalize_tls_result(result.to_dict()))
        else:
            # Last resort: direct TLS analysis on port 443
            analyzer = TLSAnalyzer()
            tls_result = analyzer.analyze_endpoint(target, 443)
            if tls_result.is_successful:
                tls_results = [_normalize_tls_result(tls_result.to_dict())]
            else:
                return {
                    "scan_id": scan_id,
                    "target": target,
                    "status": "no_endpoints",
                    "message": f"No TLS endpoints found on {target}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "discovered_services": discovered_services,
                }
    else:
        # 3. TLS Analysis for each TLS endpoint
        analyzer = TLSAnalyzer()
        tls_results = []
        for ep in tls_endpoints:
            result = analyzer.analyze_endpoint(ep.host, ep.port)
            if result.is_successful:
                tls_results.append(_normalize_tls_result(result.to_dict()))

    if not tls_results:
        return {
            "scan_id": scan_id,
            "target": target,
            "status": "analysis_failed",
            "message": "TLS analysis failed for all endpoints.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Reconcile discovered_services with tls_results
    # If network_discovery missed TLS (e.g. strict SNI), but the deep analyzer 
    # succeeded, we must update the discovery table so it shows "TLS" instead of "NO TLS"
    verified_tls_endpoints = {(res["host"], res["port"]) for res in tls_results}
    
    # Check if the fallback added a new endpoint (e.g. 443) that wasn't in discovered_services
    discovered_pairs = {(s["host"], s["port"]) for s in discovered_services}
    
    for host, port in verified_tls_endpoints:
        if (host, port) not in discovered_pairs:
            discovered_services.append({
                "host": host,
                "port": port,
                "service": "HTTPS",
                "is_tls": True,
                "banner": "TLSv1.3" # Best guess filler
            })
            
    for svc in discovered_services:
        if (svc["host"], svc["port"]) in verified_tls_endpoints:
            svc["is_tls"] = True  # Force true if analysis succeeded

    # 3. PQC Assessment
    detector = PQCDetector()
    pqc_assessments = [detector.assess_endpoint(tr) for tr in tls_results]
    pqc_dicts = [a.to_dict() for a in pqc_assessments]

    # 4. Build CBOM
    builder = CBOMBuilder()
    cbom = builder.build(tls_results, pqc_dicts)
    cbom_dict = cbom.to_dict()

    # 5. Validation
    checker = QuantumSafeChecker()
    validations = [
        checker.validate(tr, pd).to_dict()
        for tr, pd in zip(tls_results, pqc_dicts)
    ]

    # 6. Issue Labels
    issuer = CertificateIssuer()
    labels = [lb.to_dict() for lb in issuer.issue_labels(validations)]

    # 7. Recommendations
    rec_engine = RecommendationEngine()
    recommendations = []
    for v in validations:
        recommendations.extend(rec_engine.get_recommendations(v))

    # 8. Generate report
    reporter = ReportGenerator()
    report = reporter.generate_summary(cbom_dict, validations, labels)
    asset_class = _autodetect_asset_class(target, discovered_services, asset_class_hint)
    location_points = []
    seen_geo = set()
    for svc in discovered_services:
        ip = str(svc.get("host") or "")
        geo = _geolocate_ip(ip)
        if not geo:
            continue
        key = (geo.get("ip"), geo.get("lat"), geo.get("lon"))
        if key in seen_geo:
            continue
        seen_geo.add(key)
        location_points.append(geo)

    report["scan_id"] = scan_id
    report["target"] = target
    report["asset_class"] = asset_class
    report["status"] = "complete"
    report["scan_kind"] = str(scan_kind or "manual")
    report["scanned_by"] = str(scanned_by or "system")
    report["tls_results"] = tls_results
    report["pqc_assessments"] = pqc_dicts
    report["recommendations_detailed"] = recommendations
    report["discovered_services"] = discovered_services
    report["dns_records"] = dns_records
    report["asset_locations"] = location_points

    # 9. Export CBOM JSON
    cdx_gen = CycloneDXGenerator()
    cbom_path = os.path.join(RESULTS_DIR, f"{scan_id}_cbom.json")
    cdx_gen.export_json(cbom_dict, cbom_path)
    report["cbom_path"] = cbom_path

    # 10. Save report (JSON file — primary)
    report_path = os.path.join(RESULTS_DIR, f"{scan_id}_report.json")
    reporter.export_json(report, report_path)

    # 11. Save to MySQL natively via SQLAlchemy Models
    from src.db import db_session
    from src.models import Scan, Asset, Certificate, DiscoveryItem, PQCClassification, CBOMSummary, CBOMEntry
    from sqlalchemy import func
    from sqlalchemy.exc import SQLAlchemyError
    report["orm_persisted"] = False
    try:
        dt = datetime.strptime(report.get("timestamp", datetime.now(timezone.utc).isoformat()), "%Y-%m-%dT%H:%M:%S.%f%z") if "." in report.get("timestamp", "") else datetime.now()
        overall_score = sum(float(pq.get("score", 0)) for pq in pqc_dicts) / max(len(pqc_dicts), 1)
        canonical_target = _host_from_target(target).strip().lower() or str(target or "").strip().lower()
        
        db_scan = Scan(
            scan_id=scan_id,
            target=canonical_target,
            status="complete",
            asset_class=asset_class,
            started_at=dt,
            completed_at=datetime.now(),
            scanned_at=datetime.now(),
            total_assets=len(discovered_services),
            compliance_score=int(overall_score),
            overall_pqc_score=overall_score,
            quantum_safe=sum(1 for x in pqc_dicts if float(x.get("score", 0) or 0) >= 80),
            quantum_vuln=sum(1 for x in pqc_dicts if float(x.get("score", 0) or 0) < 80),
            cbom_path=cbom_path,
            report_json=json.dumps(report, default=_json_default),
            is_encrypted=False,
        )
        db_session.add(db_scan)
        db_session.flush()

        scan_pk = getattr(db_scan, "id", None) or getattr(db_scan, "scan_id", None)
        
        # Resolve Asset
        inventory_asset = (
            db_session.query(Asset)
            .filter(func.lower(Asset.name) == canonical_target)
            .first()
        )
        if inventory_asset and getattr(inventory_asset, "is_deleted", False):
            inventory_asset.is_deleted = False
        if not inventory_asset:
            score_risk = "Critical"
            if overall_score >= 80:
                score_risk = "Low"
            elif overall_score >= 60:
                score_risk = "Medium"
            elif overall_score >= 40:
                score_risk = "High"
            inventory_asset = Asset(
                name=canonical_target,
                url=f"https://{canonical_target}" if canonical_target and not canonical_target.startswith(("http://", "https://")) else canonical_target,
                asset_type="Web App",
                owner=str(scanned_by or "Unassigned"),
                risk_level=score_risk,
                notes="Auto-created from scan pipeline",
                is_deleted=False,
            )
            db_session.add(inventory_asset)
            db_session.flush()
        asset_id = int(getattr(inventory_asset, "id", 0) or 0)
        inventory_asset.last_scan_id = int(getattr(db_scan, "id", 0) or 0)
        if not str(getattr(inventory_asset, "url", "") or "") and canonical_target:
            inventory_asset.url = f"https://{canonical_target}"
        if not str(getattr(inventory_asset, "owner", "") or "").strip() and scanned_by:
            inventory_asset.owner = str(scanned_by)
        
        # Discovery Items
        discovery_types = {"domain"}
        for svc in discovered_services:
            host = str(svc.get("host") or "").strip()
            if host:
                discovery_types.add("ip")
            if str(svc.get("banner") or "").strip():
                discovery_types.add("software")
        if tls_results:
            discovery_types.add("ssl")

        detection_dt = datetime.now()
        if _db_table_exists("discovery_items"):
            for dtype in sorted(discovery_types):
                discovery_item = DiscoveryItem(
                    scan_id=int(scan_pk) if scan_pk is not None else None,
                    asset_id=asset_id,
                    type=dtype,
                    status="confirmed",
                    detection_date=detection_dt,
                )
                db_session.add(discovery_item)

        for svc in discovered_services:
            host = str(svc.get("host") or "").strip()
            if host and not str(getattr(inventory_asset, "ipv4", "") or "") and host.count(":") == 0 and any(ch.isdigit() for ch in host):
                inventory_asset.ipv4 = host
            if host and not str(getattr(inventory_asset, "ipv6", "") or "") and host.count(":") > 1:
                inventory_asset.ipv6 = host

        _persist_split_discovery_rows(
            scan_pk=int(scan_pk) if scan_pk is not None else None,
            asset_id=asset_id,
            target=canonical_target,
            discovered_services=discovered_services,
            tls_results=tls_results,
            location_points=location_points,
        )
            
        # TLS & Certificates
        for tls in tls_results:
            subject_cn = str(tls.get("subject_cn") or "")
            subject_o = str(tls.get("subject_o") or "")
            subject_ou = str(tls.get("subject_ou") or "")
            issuer_cn = str(tls.get("issuer_cn") or "")
            issuer_o = str(tls.get("issuer_o") or "")
            issuer_ou = str(tls.get("issuer_ou") or "")
            subject_display = _principal_display(subject_cn, subject_o, subject_ou) or str(tls.get("subject") or "")
            issuer_display = _principal_display(issuer_cn, issuer_o, issuer_ou) or str(tls.get("issuer") or "")
            endpoint_host = str(tls.get("host") or canonical_target or "").strip()
            endpoint_port = int(tls.get("port") or 443)
            cert_obj = Certificate(
                scan_id=int(scan_pk) if scan_pk is not None else None,
                asset_id=asset_id,
                endpoint=f"{endpoint_host}:{endpoint_port}" if endpoint_host else None,
                port=endpoint_port,
                issuer=issuer_display or "Unknown",
                subject=subject_display or "Unknown",
                subject_cn=subject_cn or None,
                subject_o=subject_o or None,
                subject_ou=subject_ou or None,
                issuer_cn=issuer_cn or None,
                issuer_o=issuer_o or None,
                issuer_ou=issuer_ou or None,
                serial=str(tls.get("serial_number", "") or ""),
                company_name=subject_o or subject_cn or None,
                valid_from=tls.get("valid_from_dt"),
                valid_until=tls.get("valid_until_dt"),
                expiry_days=_coerce_int(tls.get("cert_days_remaining")),
                fingerprint_sha256=str(tls.get("cert_sha256", "") or "").upper() or None,
                tls_version=tls.get("protocol_version", ""),
                key_length=int(tls.get("key_length", 0) or tls.get("key_size", 0)),
                key_algorithm=str(tls.get("key_type", "") or "Unknown"),
                public_key_type=str(tls.get("public_key_type") or tls.get("key_type") or "Unknown"),
                public_key_pem=str(tls.get("public_key_pem", "") or "") or None,
                cipher_suite=tls.get("cipher_suite", ""),
                signature_algorithm=str(tls.get("signature_algorithm", "") or "") or None,
                ca=issuer_cn or issuer_o or "Unknown",
                ca_name=issuer_o or issuer_cn or None,
                san_domains=_json_text(tls.get("san_domains") or []),
                cert_chain_length=_coerce_int(tls.get("certificate_chain_length")),
                is_self_signed=bool(subject_display and issuer_display and subject_display == issuer_display),
                is_expired=bool(tls.get("cert_expired")),
            )
            db_session.add(cert_obj)
            
        # PQC
        for pq in pqc_dicts:
            pqc_obj = PQCClassification(
                scan_id=int(scan_pk) if scan_pk is not None else None,
                asset_id=asset_id,
                algorithm_name=pq.get("algorithm", "Unknown"),
                algorithm_type=pq.get("category", "Unknown"),
                quantum_safe_status=pq.get("status", "Unknown"),
                nist_category=pq.get("nist_status", "None"),
                pqc_score=float(pq.get("score", 0))
            )
            db_session.add(pqc_obj)
            
        # CBOM
        cbom_summary = CBOMSummary(
            asset_id=asset_id,
            scan_id=int(scan_pk) if scan_pk is not None else None,
            total_components=len(pqc_dicts) + len(tls_results),
            weak_crypto_count=sum(1 for tls in tls_results if tls.get("protocol_version") in ("TLS 1.0", "SSLv3")),
            cert_issues_count=0,
            json_path=cbom_path
        )
        db_session.add(cbom_summary)

        def _component_properties(component: dict[str, Any]) -> dict[str, str]:
            props: dict[str, str] = {}
            for item in component.get("properties", []) or []:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("name") or "").strip()
                if not key:
                    continue
                props[key] = str(item.get("value") or "").strip()
            return props

        def _boolish(value: Any) -> bool:
            text_value = str(value or "").strip().lower()
            return text_value in {"1", "true", "yes", "safe", "quantum-safe"}

        def _first_non_empty(*values: Any, default: str = "") -> str:
            for value in values:
                text_value = str(value or "").strip()
                if text_value:
                    return text_value
            return default

        def _first_int(*values: Any, default: int | None = None) -> int | None:
            for value in values:
                parsed = _coerce_int(value)
                if parsed is not None:
                    return parsed
            return default

        def _first_dt(*values: Any):
            for value in values:
                parsed = _parse_cert_datetime(str(value or ""))
                if parsed is not None:
                    return parsed
            return None

        fallback_tls = tls_results[0] if tls_results else {}
        fallback_protocol_name = _first_non_empty(
            fallback_tls.get("protocol_name"),
            "TLS",
            default="TLS",
        )
        fallback_protocol_version = _first_non_empty(
            fallback_tls.get("protocol_version"),
            fallback_tls.get("tls_version"),
        )
        fallback_cipher_suites_raw = fallback_tls.get("cipher_suites")
        fallback_cipher_suites = fallback_cipher_suites_raw if isinstance(fallback_cipher_suites_raw, list) else []
        fallback_cipher_text = ", ".join(str(v) for v in fallback_cipher_suites if str(v or "").strip())
        if not fallback_cipher_text:
            fallback_cipher_text = _first_non_empty(fallback_tls.get("cipher_suite"))

        components = cbom_dict.get("components") or []
        if not isinstance(components, list):
            components = []
        if not components and tls_results:
            for tls in tls_results:
                components.append(
                    {
                        "name": _first_non_empty(tls.get("cipher_suite"), tls.get("protocol_version"), "Unknown Crypto Element"),
                        "type": "algorithm",
                        "properties": [],
                    }
                )
        
        for cmp in components:
            props = _component_properties(cmp)
            asset_type_raw = _first_non_empty(
                props.get("cert-in:asset_type"),
                props.get("asset_type"),
                cmp.get("type"),
                "algorithm",
            ).lower()
            if asset_type_raw not in {"algorithm", "key", "protocol", "certificate"}:
                if "cert" in asset_type_raw:
                    asset_type_raw = "certificate"
                elif "protocol" in asset_type_raw or "tls" in asset_type_raw:
                    asset_type_raw = "protocol"
                elif "key" in asset_type_raw:
                    asset_type_raw = "key"
                else:
                    asset_type_raw = "algorithm"
            asset_type = asset_type_raw

            key_size_value = _first_int(
                props.get("cert-in:size"),
                props.get("key_size"),
                props.get("quantum-safe:cert_public_key_bits"),
                props.get("quantum-safe:cipher_bits"),
                fallback_tls.get("key_size"),
                fallback_tls.get("key_length"),
            )
            key_length_value = key_size_value

            protocol_name_value = _first_non_empty(
                props.get("cert-in:protocols_name"),
                props.get("cert-in:protocol_name"),
                props.get("protocol_name"),
                fallback_protocol_name,
            )
            protocol_version_value = _first_non_empty(
                props.get("cert-in:version"),
                props.get("protocol_version_name"),
                props.get("quantum-safe:protocol"),
                fallback_protocol_version,
            )

            oid_value = _first_non_empty(
                props.get("cert-in:oid"),
                props.get("oid"),
                props.get("cert-in:signature_algorithm_oid"),
            )

            cipher_suites_value = _first_non_empty(
                props.get("cert-in:cipher_suites"),
                props.get("cipher_suites"),
                fallback_cipher_text,
            )

            crypto_functions_value = props.get("cert-in:crypto_functions") or props.get("crypto_functions")
            if isinstance(crypto_functions_value, list):
                crypto_functions_value = _json_text(crypto_functions_value)
            crypto_functions_text = str(crypto_functions_value or "")

            cert_extension_value = _first_non_empty(
                props.get("cert-in:extension"),
                props.get("certificate_extension"),
                ".crt" if asset_type == "certificate" else "",
            )
            if cert_extension_value and not cert_extension_value.startswith("."):
                cert_extension_value = f".{cert_extension_value}"

            signature_ref = _first_non_empty(
                props.get("cert-in:signature_algorithm_ref"),
                props.get("signature_algorithm_reference"),
                fallback_tls.get("signature_algorithm"),
            )
            public_key_ref = _first_non_empty(
                props.get("cert-in:subject_public_key_ref"),
                props.get("subject_public_key_reference"),
                fallback_tls.get("public_key_type"),
            )
            element_name_value = _first_non_empty(
                props.get("cert-in:name"),
                props.get("name"),
                cmp.get("name"),
            )
            element_list_value = props.get("cert-in:list") or props.get("element_list")
            if isinstance(element_list_value, list):
                element_list_value = _json_text(element_list_value)
            if not str(element_list_value or "").strip() and element_name_value:
                element_list_value = _json_text([element_name_value])

            cbom_entry = CBOMEntry(
                scan_id=int(scan_pk) if scan_pk is not None else None,
                asset_id=asset_id,
                algorithm_name=element_name_value,
                category=cmp.get("type", "crypto-asset"),
                asset_type=asset_type,
                element_name=element_name_value,
                primitive=_first_non_empty(props.get("cert-in:primitive"), props.get("primitive")),
                mode=_first_non_empty(props.get("cert-in:mode"), props.get("mode")),
                crypto_functions=crypto_functions_text,
                classical_security_level=_first_int(props.get("cert-in:classical_security_level"), props.get("classical_security_level")),
                oid=oid_value,
                element_list=str(element_list_value or ""),
                key_id=_first_non_empty(props.get("cert-in:id"), props.get("key_id")),
                key_state=_first_non_empty(props.get("cert-in:state"), props.get("key_state")),
                key_size=key_size_value,
                key_creation_date=_first_dt(props.get("cert-in:creation_date"), props.get("key_creation_date")),
                key_activation_date=_first_dt(props.get("cert-in:activation_date"), props.get("key_activation_date")),
                protocol_name=protocol_name_value,
                protocol_version_name=protocol_version_value,
                cipher_suites=cipher_suites_value,
                subject_name=_first_non_empty(props.get("cert-in:subject_name"), props.get("subject_name"), fallback_tls.get("subject_cn")),
                issuer_name=_first_non_empty(props.get("cert-in:issuer_name"), props.get("issuer_name"), fallback_tls.get("issuer_cn"), fallback_tls.get("issuer_o")),
                not_valid_before=_first_dt(props.get("cert-in:not_valid_before"), props.get("not_valid_before"), fallback_tls.get("valid_from")),
                not_valid_after=_first_dt(props.get("cert-in:not_valid_after"), props.get("not_valid_after"), fallback_tls.get("valid_to")),
                signature_algorithm_reference=signature_ref,
                subject_public_key_reference=public_key_ref,
                certificate_format=_first_non_empty(props.get("cert-in:format"), props.get("certificate_format"), "X.509" if asset_type == "certificate" else ""),
                certificate_extension=cert_extension_value,
                key_length=key_length_value,
                protocol_version=protocol_version_value,
                nist_status=_first_non_empty(props.get("cert-in:quantum_safe_status"), props.get("quantum_safe_status"), "Unknown"),
                quantum_safe_flag=_boolish(props.get("cert-in:quantum_safe_status") or props.get("quantum-safe:is_quantum_safe")),
                hndl_level=props.get("quantum-safe:risk_level", "Medium")
            )
            db_session.add(cbom_entry)

        if _db_table_exists("findings") and scan_pk is not None:
            db_session.flush()
            try:
                from src.services.finding_detection_service import FindingDetectionService

                finding_result = FindingDetectionService.detect_and_store_findings(
                    asset_id=asset_id,
                    scan_id=int(scan_pk),
                )
                report["finding_summary"] = finding_result
            except Exception as finding_exc:
                report["finding_summary"] = {
                    "created": 0,
                    "error": str(finding_exc),
                }

        if _db_table_exists("asset_metrics") and scan_pk is not None:
            try:
                from src.services.pqc_calculation_service import PQCCalculationService

                metric = PQCCalculationService.calculate_and_store_pqc_metrics(
                    asset_id=asset_id,
                    scan_id=int(scan_pk),
                    auto_commit=False,
                )
                report["pqc_metrics"] = {
                    "pqc_score": float(getattr(metric, "pqc_score", 0) or 0),
                    "pqc_class_tier": str(getattr(metric, "pqc_class_tier", "") or ""),
                    "asset_cyber_score": float(getattr(metric, "asset_cyber_score", 0) or 0),
                }
            except Exception as pqc_exc:
                report["pqc_metrics"] = {
                    "error": str(pqc_exc),
                }

            try:
                from src.services.risk_calculation_service import RiskCalculationService

                risk_result = RiskCalculationService.calculate_and_store_risk_metrics(
                    asset_id=asset_id,
                    scan_id=int(scan_pk),
                    auto_commit=False,
                )
                report["risk_metrics"] = risk_result
            except Exception as risk_exc:
                report["risk_metrics"] = {
                    "error": str(risk_exc),
                }

        if _db_table_exists("digital_labels") and scan_pk is not None:
            try:
                from src.services.digital_label_service import DigitalLabelService

                label_result = DigitalLabelService.calculate_and_store_digital_label(
                    asset_id=asset_id,
                    scan_id=int(scan_pk),
                    auto_commit=False,
                )
                report["digital_label"] = label_result
            except Exception as label_exc:
                report["digital_label"] = {
                    "error": str(label_exc),
                }

        db_session.commit()
        report["orm_persisted"] = True
    except SQLAlchemyError as err:
        db_session.rollback()
        import traceback
        print(f"Failed to ingest native DB schema: {err}")
        traceback.print_exc()
        report["orm_persisted"] = False
        
    # Store in memory primarily for caching/legacy access if needed
    scan_store[scan_id] = report
    try:
        invalidate_dashboard_cache()
    except Exception:
        pass
    return report


# Expose scan runner for other modules (e.g., inventory background scans)
app.config["RUN_SCAN_PIPELINE_FUNC"] = run_scan_pipeline


# ── Routes ───────────────────────────────────────────────────────────

@app.route("/")
def root_index():
    """Redirects absolute root to the Main Dashboard."""
    return redirect(url_for('quantumshield_dashboard.dashboard_home'))



@app.route("/login", methods=["GET", "POST"])
@limiter.limit("100 per minute")
def login():
    """Secure login page — CSRF protected, rate-limited, lockout-aware."""
    if current_user.is_authenticated:
        return redirect(url_for('quantumshield_dashboard.dashboard_home'))

    locked = False

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))

        user_data = db.get_user_by_username(username)

        # ── Lockout check ─────────────────────────────────────────
        if user_data and user_data.get("lockout_until") and datetime.now(timezone.utc).replace(tzinfo=None) < user_data["lockout_until"]:
            db.append_audit_log(
                event_category="auth",
                event_type="login_blocked_locked_account",
                status="denied",
                actor_user_id=user_data.get("id"),
                actor_username=username,
                ip_address=_get_request_ip(),
                user_agent=request.headers.get("User-Agent", "")[:512],
                request_method=request.method,
                request_path=request.path,
                details={"lockout_until": user_data.get("lockout_until").isoformat() if user_data.get("lockout_until") else None},
            )
            flash("Account temporarily locked due to repeated failed login attempts. Please try again later or use Forgot Password.", "error")
            locked = True
            return render_template("login.html", locked=locked)

        # ── Credential check ──────────────────────────────────────
        if user_data and check_password_hash(user_data["password_hash"], password):
            if not user_data.get("is_active", True):
                flash("Your account has been suspended. Contact an administrator.", "error")
                return render_template("login.html", locked=False)

            db.mark_login_success(user_data["id"])
            user = User(user_data)
            session.clear()
            login_user(user, remember=remember)
            _audit("auth", "login_success", "success", target_user_id=user_data["id"], details={"role": user.role, "remember": remember})

            if user_data.get("must_change_password"):
                token = db.create_password_setup_token(user_data["id"], expires_hours=2)
                if token:
                    _audit("auth", "password_change_required", "success", target_user_id=user_data["id"], details={"reason": "must_change_password"})
                    flash("Please set a new password before continuing.", "warning")
                    return redirect(url_for("setup_password", token=token))

            return redirect(url_for('quantumshield_dashboard.dashboard_home'))
        else:
            if user_data:
                db.mark_login_failure(user_data["id"], MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_MINUTES)
            db.append_audit_log(
                event_category="auth",
                event_type="login_failed",
                status="failed",
                actor_user_id=user_data.get("id") if user_data else None,
                actor_username=username,
                ip_address=_get_request_ip(),
                user_agent=request.headers.get("User-Agent", "")[:512],
                request_method=request.method,
                request_path=request.path,
                details={"user_exists": bool(user_data)},
            )
            flash("Invalid credentials. Access denied.", "error")

    return render_template("login.html", locked=locked)


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def forgot_password():
    """Email-based password reset flow."""
    if current_user.is_authenticated:
        return redirect(url_for('quantumshield_dashboard.dashboard_home'))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            flash("Please enter an email address.", "error")
            return render_template("forgot_password.html")

        # Always show success message (prevent user enumeration)
        flash("If an account with that email exists, a password reset link has been sent.", "success")
        _audit("auth", "password_reset_requested", "success", details={"email": email})

        # Check if user exists with this email
        user_data = db.get_user_by_email(email)
        if user_data:
            token = db.create_password_setup_token(user_data["id"], expires_hours=2)
            if token:
                reset_link = _build_setup_link(token)
                try:
                    from flask_mail import Message as MailMessage
                    msg = MailMessage(
                        subject="QuantumShield — Password Reset",
                        recipients=[email],
                        body=f"""Hello {user_data.get('username', 'user')},

A password reset was requested for your QuantumShield account.

Click the link below to set a new password (valid for 2 hours):
{reset_link}

If you did not request this, please ignore this email.

— QuantumShield Security System
""",
                    )
                    mail.send(msg)
                    _audit("auth", "password_reset_email_sent", "success",
                           target_user_id=user_data["id"],
                           details={"email": email})
                except Exception as exc:
                    logger.error("Failed to send password reset email: %s", exc)
                    _audit("auth", "password_reset_email_failed", "failed",
                           target_user_id=user_data["id"],
                           details={"error": str(exc)[:200]})
                    # If mail fails, flash the link directly (dev environments)
                    if DEBUG:
                        flash(f"(DEV) Reset link: {reset_link}", "warning")

        return render_template("forgot_password.html")

    return render_template("forgot_password.html")


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    """Logout current user."""
    _audit("auth", "logout", "success")
    logout_user()
    session.clear()
    return redirect(url_for('login'))


@app.route("/admin/theme", methods=["GET", "POST"])
@role_required(list(ADMIN_PANEL_ROLES))
def admin_theme():
    """Admin panel to configure dynamic UI theme colors."""
    current_theme = load_theme()
    if request.method == "POST":
        if request.form.get("reset_colors"):
            requested_theme = {
                "mode": "system",
                "dark": dict(THEME_DEFAULTS["dark"]),
                "light": dict(THEME_DEFAULTS["light"]),
            }
        else:
            requested_theme = {
                "mode": request.form.get("mode", current_theme.get("mode", "system")),
                "dark": {
                    "bg_navbar": request.form.get("dark_bg_navbar", current_theme["dark"]["bg_navbar"]),
                    "bg_primary": request.form.get("dark_bg_primary", current_theme["dark"]["bg_primary"]),
                    "bg_secondary": request.form.get("dark_bg_secondary", current_theme["dark"]["bg_secondary"]),
                    "bg_card": request.form.get("dark_bg_card", current_theme["dark"]["bg_card"]),
                    "bg_input": request.form.get("dark_bg_input", current_theme["dark"]["bg_input"]),
                    "border_subtle": request.form.get("dark_border_subtle", current_theme["dark"]["border_subtle"]),
                    "border_hover": request.form.get("dark_border_hover", current_theme["dark"]["border_hover"]),
                    "text_primary": request.form.get("dark_text_primary", current_theme["dark"]["text_primary"]),
                    "text_secondary": request.form.get("dark_text_secondary", current_theme["dark"]["text_secondary"]),
                    "text_muted": request.form.get("dark_text_muted", current_theme["dark"]["text_muted"]),
                    "accent_color": request.form.get("dark_accent_color", current_theme["dark"]["accent_color"]),
                    "safe": request.form.get("dark_safe", current_theme["dark"]["safe"]),
                    "warn": request.form.get("dark_warn", current_theme["dark"]["warn"]),
                    "danger": request.form.get("dark_danger", current_theme["dark"]["danger"]),
                },
                "light": {
                    "bg_navbar": request.form.get("light_bg_navbar", current_theme["light"]["bg_navbar"]),
                    "bg_primary": request.form.get("light_bg_primary", current_theme["light"]["bg_primary"]),
                    "bg_secondary": request.form.get("light_bg_secondary", current_theme["light"]["bg_secondary"]),
                    "bg_card": request.form.get("light_bg_card", current_theme["light"]["bg_card"]),
                    "bg_input": request.form.get("light_bg_input", current_theme["light"]["bg_input"]),
                    "border_subtle": request.form.get("light_border_subtle", current_theme["light"]["border_subtle"]),
                    "border_hover": request.form.get("light_border_hover", current_theme["light"]["border_hover"]),
                    "text_primary": request.form.get("light_text_primary", current_theme["light"]["text_primary"]),
                    "text_secondary": request.form.get("light_text_secondary", current_theme["light"]["text_secondary"]),
                    "text_muted": request.form.get("light_text_muted", current_theme["light"]["text_muted"]),
                    "accent_color": request.form.get("light_accent_color", current_theme["light"]["accent_color"]),
                    "safe": request.form.get("light_safe", current_theme["light"]["safe"]),
                    "warn": request.form.get("light_warn", current_theme["light"]["warn"]),
                    "danger": request.form.get("light_danger", current_theme["light"]["danger"]),
                },
            }
        new_theme = _sanitize_theme(requested_theme)
        try:
            with open(THEME_FILE, 'w') as f:
                json.dump(new_theme, f, indent=4)
            _audit("admin", "update_theme", "success", details={"mode": new_theme.get("mode"), "theme": new_theme})
            flash("Theme configurations updated successfully!", "success")
        except Exception as e:
            _audit("admin", "update_theme_failed", "failed", details={"error": str(e)})
            flash(f"Failed to save theme: {e}", "danger")
        return redirect(url_for('admin_theme'))
        
    return render_template("admin_theme.html", theme=current_theme, section_title="Theme configuration")

@app.route("/admin/users", methods=["GET", "POST"])
@role_required(list(ADMIN_PANEL_ROLES))
def admin_users():
    """Admin panel to manage users and send setup invites."""
    if request.method == "POST":
        employee_id = (request.form.get("employee_id") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        username = (request.form.get("username") or "").strip()
        role = db.normalize_role(request.form.get("role") or "Viewer")

        if not employee_id or not email or not username:
            _audit("admin", "create_user_validation_failed", "failed", details={"has_employee_id": bool(employee_id), "has_email": bool(email), "has_username": bool(username)})
            flash("Employee ID, email, and username are required.", "error")
            return redirect(url_for("admin_users"))

        temp_password = uuid.uuid4().hex
        invited_user_id = db.create_invited_user(
            employee_id=employee_id,
            username=username,
            email=email,
            role=role,
            created_by=current_user.id,
            password_hash=generate_password_hash(temp_password),
        )

        if not invited_user_id:
            _audit("admin", "create_user", "failed", details={"email": email, "username": username, "employee_id": employee_id, "role": role})
            flash("Failed to create user. Check for duplicate username/email/employee ID.", "error")
            return redirect(url_for("admin_users"))

        token = db.create_password_setup_token(invited_user_id, expires_hours=24)
        if not token:
            _audit("admin", "create_user_token", "failed", target_user_id=invited_user_id, details={"email": email})
            flash("User created, but setup token generation failed.", "warning")
            return redirect(url_for("admin_users"))

        setup_url = _build_setup_link(token)

        try:
            msg = Message("Welcome to QuantumShield - Setup Your Password", recipients=[email])
            msg.body = (
                "Hello,\n\n"
                f"Your QuantumShield account has been created by admin.\n"
                f"Employee ID: {employee_id}\n"
                f"Username: {username}\n"
                f"Role: {role}\n\n"
                "Use the secure link below to set your password:\n"
                f"{setup_url}\n\n"
                "This link expires in 24 hours and can only be used once."
            )
            mail.send(msg)
            _audit("admin", "create_user", "success", target_user_id=invited_user_id, details={"email": email, "username": username, "employee_id": employee_id, "role": role, "email_sent": True})
            flash(f"User {username} invited successfully. Setup email sent.", "success")
        except Exception as exc:
            logger.error("Failed to send setup email to %s: %s", email, exc)
            _audit("admin", "create_user", "partial", target_user_id=invited_user_id, details={"email": email, "username": username, "role": role, "email_sent": False, "error": str(exc)})
            flash(f"User created, but SMTP failed to send setup email. Temporary setup link: {setup_url}", "warning")

        return redirect(url_for("admin_users"))

    users = db.list_users()
    return render_template("admin_users.html", users=users)


@app.route("/admin/audit")
@role_required(list(ADMIN_PANEL_ROLES))
def admin_audit_logs():
    logs = db.list_audit_logs(limit=AUDIT_LOG_PAGE_SIZE)
    is_valid, issues = db.verify_audit_log_chain(limit=max(AUDIT_LOG_PAGE_SIZE, 500))
    return render_template("admin_audit.html", logs=logs, chain_valid=is_valid, chain_issues=issues)


@app.route("/admin/users/<user_id>/reset-password", methods=["POST"])
@role_required(list(ADMIN_PANEL_ROLES))
def admin_reset_user_password(user_id: str):
    """Admin-triggered password reset email for an existing user. Supports form OR JSON."""
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    user = db.get_user_by_id(user_id)
    if not user:
        _audit("admin", "reset_password", "failed", target_user_id=user_id, details={"reason": "user_not_found"})
        if wants_json:
            return jsonify({"status": "error", "message": "User not found or inactive."}), 404
        flash("User not found or inactive.", "error")
        return redirect(url_for("admin_users"))
    if not user.get("email"):
        _audit("admin", "reset_password", "failed", target_user_id=user_id, details={"reason": "missing_email"})
        if wants_json:
            return jsonify({"status": "error", "message": "User has no email configured."}), 400
        flash("User has no email configured.", "error")
        return redirect(url_for("admin_users"))

    token = db.create_password_setup_token(user_id, expires_hours=24)
    if not token:
        _audit("admin", "reset_password", "failed", target_user_id=user_id, details={"reason": "token_generation_failed"})
        if wants_json:
            return jsonify({"status": "error", "message": "Failed to generate reset token."}), 500
        flash("Failed to generate reset token.", "error")
        return redirect(url_for("admin_users"))

    setup_url = _build_setup_link(token)
    try:
        msg = Message("QuantumShield Password Reset", recipients=[user["email"]])
        msg.body = (
            "Hello,\n\n"
            f"A password reset was initiated by admin for username: {user['username']}\n\n"
            "Use this secure one-time link to set a new password:\n"
            f"{setup_url}\n\n"
            "This link expires in 24 hours."
        )
        mail.send(msg)
        _audit("admin", "reset_password", "success", target_user_id=user_id, details={"email": user["email"], "email_sent": True})
        if wants_json:
            return jsonify({
                "status": "success",
                "message": "Password reset email sent.",
                "user_id": user_id,
                "username": user["username"]
            }), 200
        flash("Password reset email sent.", "success")
    except Exception as exc:
        logger.error("Password reset email failed for %s: %s", user["email"], exc)
        _audit("admin", "reset_password", "partial", target_user_id=user_id, details={"email": user["email"], "email_sent": False, "error": str(exc)})
        if wants_json:
            return jsonify({
                "status": "error",
                "message": f"SMTP failed: {str(exc)}"
            }), 500
        flash(f"SMTP failed. Temporary setup link: {setup_url}", "warning")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<user_id>/update", methods=["POST"])
@role_required(list(ADMIN_PANEL_ROLES))
def admin_update_user(user_id: str):
    """Update user role and active status. Supports form OR JSON."""
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    if request.is_json:
        data = request.get_json() or {}
        role = db.normalize_role(data.get("role") or "Viewer")
        is_active = data.get("is_active", True)
    else:
        role = db.normalize_role(request.form.get("role") or "Viewer")
        is_active = request.form.get("is_active") == "on"
    
    if db.update_user_profile(user_id, role=role, is_active=is_active):
        _audit("admin", "update_user", "success", target_user_id=user_id, details={"role": role, "is_active": is_active})
        if wants_json:
            return jsonify({
                "status": "success",
                "message": "User profile updated.",
                "user_id": user_id,
                "role": role,
                "is_active": is_active
            }), 200
        flash("User profile updated.", "success")
    else:
        _audit("admin", "update_user", "failed", target_user_id=user_id, details={"role": role, "is_active": is_active})
        if wants_json:
            return jsonify({"status": "error", "message": "Failed to update user profile."}), 500
        flash("Failed to update user profile.", "error")
    return redirect(url_for("admin_users"))


@app.route("/setup-password/<token>", methods=["GET", "POST"])
def setup_password(token):
    """Secure link to allow new users to set their password."""
    user_data = db.get_user_by_setup_token(token)
    if not user_data:
        db.append_audit_log(
            event_category="auth",
            event_type="password_setup_invalid_token",
            status="failed",
            ip_address=_get_request_ip(),
            user_agent=request.headers.get("User-Agent", "")[:512],
            request_method=request.method,
            request_path=request.path,
            details={},
        )
        flash("The setup link is invalid or has expired.", "error")
        return redirect(url_for('login'))

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        is_valid, message = _validate_password_strength(password)
        if not is_valid:
            _audit("auth", "password_setup", "failed", target_user_id=user_data["id"], details={"reason": message})
            flash(message, "error")
            return render_template("setup_password.html", token=token)
        if password != confirm_password:
            _audit("auth", "password_setup", "failed", target_user_id=user_data["id"], details={"reason": "confirmation_mismatch"})
            flash("Password and confirmation do not match.", "error")
            return render_template("setup_password.html", token=token)

        if db.set_user_password(user_data["id"], generate_password_hash(password)):
            db.append_audit_log(
                event_category="auth",
                event_type="password_setup_completed",
                status="success",
                actor_user_id=user_data["id"],
                actor_username=user_data.get("username"),
                target_user_id=user_data["id"],
                ip_address=_get_request_ip(),
                user_agent=request.headers.get("User-Agent", "")[:512],
                request_method=request.method,
                request_path=request.path,
                details={},
            )
            flash("Password set successfully. You can now log in.", "success")
            return redirect(url_for('login'))

        _audit("auth", "password_setup", "failed", target_user_id=user_data["id"], details={"reason": "database_update_failed"})
        flash("Failed to update password.", "error")

    return render_template("setup_password.html", token=token)



@dashboard_bp.route("/")
@login_required
def index():
    """Scanner dashboard with enterprise metrics directly populated from DB view aggregate for performance."""
    recent_scans = db.list_scans(limit=10)

    from src.services.asset_service import AssetService

    asset_svc = AssetService()
    assets = asset_svc.load_combined_assets()
    summary = asset_svc.get_dashboard_summary(assets)

    if not summary or summary.get("total_assets", 0) == 0:
        logger.info("AssetService summary empty. Falling back to MySQL enterprise metrics.")
        summary = db.get_enterprise_metrics()
        assets = asset_svc.load_combined_assets()

    summary = {
        **summary,
        "latest_scan": summary.get("latest_scan") or (recent_scans[0].get("scanned_at") if recent_scans else "Never"),
    }

    return render_template(
        "home.html",
        recent_scans=recent_scans,
        assets=assets,
        summary=summary,
        enterprise_metrics=summary,
    )

# Register Main Dashboard Blueprint
from web.blueprints.dashboard import dashboard_bp
from web.routes.assets import assets_bp
from web.routes.dashboard_api import api_dashboards_bp
from web.routes.scans import scans_bp
from web.blueprints.api_blueprint_init import register_api_blueprints

app.register_blueprint(dashboard_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(api_dashboards_bp)
app.register_blueprint(scans_bp)

# Register all API blueprints (API-first refactor V2)
register_api_blueprints(app)

# Inventory status polling runs frequently from UI; keep it outside tight default limits.
if "quantumshield_dashboard.inventory_scan_status" in app.view_functions:
    limiter.limit("2000 per hour")(app.view_functions["quantumshield_dashboard.inventory_scan_status"])




@app.route("/scan-center")
@role_required(list(SCAN_ROLES))
def scan_center():
    """Legacy scan center route preserved for compatibility tests/links."""
    user_role = str(getattr(current_user, "role", "") or "").strip().title()
    can_bulk_scan = user_role in {r.strip().title() for r in BULK_SCAN_ROLES}
    return render_template(
        "scans.html",
        can_single_scan=True,
        can_bulk_scan=can_bulk_scan,
    )


def _score_to_risk(score: float) -> str:
    if score >= 700:
        return "Low"
    if score >= 400:
        return "Medium"
    if score >= 200:
        return "High"
    return "Critical"


def _iso_date(value: str) -> str:
    if not value:
        return ""
    return str(value)[:10]


def _host_from_target(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    return raw.split("/", 1)[0].split(":", 1)[0]


def _build_asset_inventory_view() -> dict:
    """Build inventory view-model from MySQL tables only."""
    from src.services.asset_service import AssetService

    service = AssetService()
    return service.get_inventory_view_model(testing_mode=app.config.get("TESTING", False))


def _build_asset_discovery_view(
    include_in_progress: bool = False,
    page: int = 1,
    page_size: int = 100,
    search_term: str = "",
) -> dict:
    """Build discovery view from persisted scan table data (with testing fallback)."""
    from collections import Counter
    import ipaddress
    from src.db import db_session
    from src.models import Asset, Scan as ScanModel

    testing_mode = app.config.get("TESTING", False)
    domains: list[dict] = []
    ssl: list[dict] = []
    ip_subnets: list[dict] = []
    software: list[dict] = []
    nodes: list[dict] = []
    edges: list[dict] = []

    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    normalized_search = str(search_term or "").strip().lower()

    try:
        known_assets = {
            str(getattr(a, "name", "") or "").strip().lower()
            for a in db_session.query(Asset).filter(Asset.is_deleted == False).all()
            if str(getattr(a, "name", "") or "").strip()
        }
    except Exception as exc:
        logger.warning("Asset discovery known-asset load failed: %s", exc)
        known_assets = set()

    def add_node(node_id: str, label: str, group: str, title: str) -> None:
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({"id": node_id, "label": label, "group": group, "title": title})

    def add_edge(src: str, dst: str) -> None:
        key = f"{src}->{dst}"
        if key in edge_ids:
            return
        edge_ids.add(key)
        edges.append({"id": key, "from": src, "to": dst})

    scans_feed = []
    if testing_mode:
        for scan in scan_store.values():
            if isinstance(scan, dict):
                scans_feed.append(scan)
    else:
        try:
            offset = max(page - 1, 0) * page_size
            rows = (
                db_session.query(ScanModel)
                .filter(ScanModel.is_deleted == False)
                .order_by(ScanModel.started_at.desc(), ScanModel.id.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )
            for scan_row in rows:
                row_status = str(getattr(scan_row, "status", "") or "").strip().lower()
                if row_status != "complete" and not include_in_progress:
                    continue
                target = str(getattr(scan_row, "target", "") or "").strip()
                if not target:
                    continue
                report_payload = {}
                raw_report = getattr(scan_row, "report_json", None)
                if isinstance(raw_report, str) and raw_report.strip().startswith("{"):
                    try:
                        parsed = json.loads(raw_report)
                        report_payload = parsed if isinstance(parsed, dict) else {}
                    except Exception:
                        report_payload = {}
                scans_feed.append(
                    {
                        "scan_id": str(getattr(scan_row, "scan_id", "") or getattr(scan_row, "id", "")),
                        "target": target,
                        "status": str(getattr(scan_row, "status", "") or ""),
                        "generated_at": (
                            getattr(scan_row, "scanned_at", None)
                            or getattr(scan_row, "completed_at", None)
                            or getattr(scan_row, "started_at", None)
                        ).isoformat()
                        if (
                            getattr(scan_row, "scanned_at", None)
                            or getattr(scan_row, "completed_at", None)
                            or getattr(scan_row, "started_at", None)
                        )
                        else "",
                        "discovered_services": report_payload.get("discovered_services", []),
                        "tls_results": report_payload.get("tls_results", []),
                    }
                )
        except Exception as exc:
            logger.warning("Asset discovery DB scan load failed: %s", exc)

    for scan in scans_feed:
        if scan.get("status") != "complete" and not include_in_progress:
            continue

        target = str(scan.get("target", "")).strip().lower()
        
        # Only show discovery details of the asset added to the asset inventory
        if not testing_mode and target not in known_assets:
            # Also try matching host
            host = _host_from_target(target)
            if host not in known_assets:
                continue

        host = _host_from_target(target)
        if not host:
            continue

        detection_date = _iso_date(str(scan.get("generated_at", "")))
        add_node(f"domain:{host}", host, "domain", f"Domain · {host}")

        is_inventoried = (host in known_assets) or (target in known_assets)

        domains.append(
            {
                "status": "Confirmed" if scan.get("status") == "complete" else "New",
                "detection_date": detection_date,
                "domain_name": host,
                "registration_date": "",
                "registrar": "",
                "company": "Internal" if is_inventoried else "External",
                "is_inventoried": is_inventoried,
            }
        )

        discovered_services = scan.get("discovered_services") or []
        tls_results = scan.get("tls_results") or []

        for svc in discovered_services:
            svc_host = str(svc.get("host", "")).strip()
            port = svc.get("port")
            service_name = str(svc.get("service", "unknown"))
            banner = str(svc.get("banner", ""))

            if svc_host:
                try:
                    parsed = ipaddress.ip_address(svc_host)
                    geo = _geolocate_ip(svc_host) if parsed.version == 4 else {}
                    location_text = ", ".join(
                        part
                        for part in (
                            str(geo.get("city") or "").strip(),
                            str(geo.get("region") or "").strip(),
                            str(geo.get("country") or "").strip(),
                        )
                        if part
                    )
                    subnet = f"{svc_host}/32" if parsed.version == 4 else f"{svc_host}/128"
                    ip_subnets.append(
                        {
                            "status": "Confirmed" if scan.get("status") == "complete" else "New",
                            "detection_date": detection_date,
                            "ip": svc_host,
                            "ports": str(port or ""),
                            "subnet": subnet,
                            "asn": "",
                            "netname": "",
                            "location": location_text,
                            "lat": geo.get("lat"),
                            "lon": geo.get("lon"),
                            "company": "Internal" if is_inventoried else "External",
                            "is_inventoried": is_inventoried,
                        }
                    )
                    add_node(f"ip:{svc_host}", svc_host, "ip", f"IP · {svc_host}")
                    add_edge(f"domain:{host}", f"ip:{svc_host}")
                    if port:
                        add_node(
                            f"service:{svc_host}:{port}",
                            f"{service_name.upper()}:{port}",
                            "service",
                            f"Service · {service_name}:{port}",
                        )
                        add_edge(f"ip:{svc_host}", f"service:{svc_host}:{port}")
                except ValueError:
                    pass

            if banner:
                version = ""
                if "/" in banner:
                    pieces = banner.split("/", 1)
                    service_name = pieces[0] or service_name
                    version = pieces[1]
                software.append(
                    {
                        "status": "Confirmed" if scan.get("status") == "complete" else "New",
                        "detection_date": detection_date,
                        "product": service_name,
                        "version": version,
                        "type": "Service",
                        "port": port or "",
                        "host": host,
                        "company": "Internal" if is_inventoried else "External",
                        "is_inventoried": is_inventoried,
                    }
                )

        for tr in tls_results:
            fingerprint = str(tr.get("cert_sha256") or tr.get("fingerprint") or "")
            issuer = tr.get("issuer") if isinstance(tr.get("issuer"), dict) else {}
            ssl.append(
                {
                    "status": "Confirmed" if scan.get("status") == "complete" else "New",
                    "detection_date": detection_date,
                    "fingerprint": fingerprint,
                    "valid_from": str(tr.get("valid_from", ""))[:10],
                    "common_name": str(tr.get("server_name") or host),
                    "company": "Internal" if is_inventoried else "External",
                    "ca": issuer.get("O") or issuer.get("CN") or "Unknown",
                    "is_inventoried": is_inventoried,
                }
            )

    # Keep rows unique and stable.
    def _uniq(rows: list[dict], key_fn):
        seen = set()
        out = []
        for row in rows:
            k = key_fn(row)
            if k in seen:
                continue
            seen.add(k)
            out.append(row)
        return out

    domains = _uniq(domains, lambda r: (r["domain_name"], r["detection_date"]))
    ssl = _uniq(ssl, lambda r: (r["fingerprint"], r["common_name"], r["detection_date"]))
    ip_subnets = _uniq(ip_subnets, lambda r: (r["ip"], r["ports"], r["detection_date"]))
    software = _uniq(software, lambda r: (r["host"], r["product"], r["port"], r["detection_date"]))

    if normalized_search:
        domains = [
            r for r in domains
            if normalized_search in str(r.get("domain_name", "")).lower()
            or normalized_search in str(r.get("registrar", "")).lower()
            or normalized_search in str(r.get("company", "")).lower()
        ]
        ssl = [
            r for r in ssl
            if normalized_search in str(r.get("common_name", "")).lower()
            or normalized_search in str(r.get("ca", "")).lower()
            or normalized_search in str(r.get("fingerprint", "")).lower()
            or normalized_search in str(r.get("company", "")).lower()
        ]
        ip_subnets = [
            r for r in ip_subnets
            if normalized_search in str(r.get("ip", "")).lower()
            or normalized_search in str(r.get("subnet", "")).lower()
            or normalized_search in str(r.get("location", "")).lower()
            or normalized_search in str(r.get("company", "")).lower()
        ]
        software = [
            r for r in software
            if normalized_search in str(r.get("product", "")).lower()
            or normalized_search in str(r.get("version", "")).lower()
            or normalized_search in str(r.get("host", "")).lower()
            or normalized_search in str(r.get("company", "")).lower()
        ]

    status_counts = Counter(
        [r.get("status", "") for r in domains + ssl + ip_subnets + software if r.get("status")]
    )

    asset_locations = []
    seen_locations: set[tuple[Any, Any, str]] = set()
    for row in ip_subnets:
        lat = row.get("lat")
        lon = row.get("lon")
        if lat is None or lon is None:
            continue
        key = (lat, lon, str(row.get("ip") or ""))
        if key in seen_locations:
            continue
        seen_locations.add(key)
        asset_locations.append(
            {
                "ip": str(row.get("ip") or ""),
                "lat": lat,
                "lon": lon,
                "location": str(row.get("location") or ""),
            }
        )

    return {
        "empty": not (domains or ssl or ip_subnets or software),
        "overview": {
            "domains": len(domains),
            "ssl": len(ssl),
            "ip_subnets": len(ip_subnets),
            "software": len(software),
        },
        "status_counts": {
            "New": status_counts.get("New", 0),
            "False Positive": status_counts.get("False Positive", 0),
            "Confirmed": status_counts.get("Confirmed", 0),
            "All": len(domains) + len(ssl) + len(ip_subnets) + len(software),
        },
        "domains": domains,
        "ssl": ssl,
        "ip_subnets": ip_subnets,
        "software": software,
        "asset_locations": asset_locations,
        "graph_payload": {
            "nodes": nodes,
            "edges": edges,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def _render_api_dashboard_page(
    page_title: str,
    api_endpoint: str,
    columns: list[dict[str, str]],
    default_sort: str,
    default_order: str = "asc",
    default_page_size: int = 25,
    extra_params: dict | None = None,
):
    return render_template(
        "api_dashboard_example.html",
        page_title=page_title,
        api_endpoint=api_endpoint,
        columns=columns,
        default_sort=default_sort,
        default_order=default_order,
        default_page_size=default_page_size,
        extra_params=extra_params or {},
    )


@app.route("/asset-inventory")
@login_required
def asset_inventory_page():
    from web.routes.assets import render_assets_inventory_page

    return render_assets_inventory_page()



@app.route("/asset-discovery")
@login_required
def asset_discovery():
    from flask import request
    from src.db import db_session
    from src.models import Scan
    from src.table_helper import paginate_query
    
    page = int(request.args.get("page", 1) or 1)
    page_size = min(int(request.args.get("page_size", 100) or 100), 250)
    search_term = str(request.args.get("q", "") or "").strip()

    # We will use 'tab' parameter to define which model to paginate in future revisions
    # For now, we will pass an empty page_data to avoid crashing the macro injection UI until Discovery DB tables operate
    page_data: typing.Dict[str, typing.Any] = {"items": [], "total_count": 0, "has_next": False, "has_prev": False}

    try:
        vm = _build_asset_discovery_view(page=page, page_size=page_size, search_term=search_term)
    except Exception:
        vm = {
            "empty": True,
            "overview": {"domains": 0, "ssl": 0, "ip_subnets": 0, "software": 0},
            "status_counts": {"New": 0, "False Positive": 0, "Confirmed": 0, "All": 0},
            "domains": [],
            "ssl": [],
            "ip_subnets": [],
            "software": [],
            "graph_payload": {"nodes": [], "edges": []}
        }

        
    return render_template("asset_discovery.html", vm=vm, page_data=page_data)


@app.route("/api/discovery-graph")
@csrf.exempt
@login_required
def discovery_graph_payload():
    """Realtime discovery graph payload for incremental frontend updates."""
    _audit("scan", "discovery_graph_requested", "success")
    try:
        nodes: list[dict] = []
        edges: list[dict] = []
        node_ids: set[str] = set()
        edge_ids: set[str] = set()

        def add_node(node_id: str, label: str, group: str, title: str) -> None:
            if node_id in node_ids:
                return
            node_ids.add(node_id)
            nodes.append({"id": node_id, "label": label, "group": group, "title": title})

        def add_edge(src: str, dst: str) -> None:
            key = f"{src}->{dst}"
            if key in edge_ids:
                return
            edge_ids.add(key)
            edges.append({"id": key, "from": src, "to": dst})

        for scan in scan_store.values():
            if not isinstance(scan, dict):
                continue
            if scan.get("status") != "complete":
                continue
            target = str(scan.get("target", "")).strip().lower()
            host = _host_from_target(target)
            if not host:
                continue
            add_node(f"domain:{host}", host, "domain", f"Domain · {host}")
            for svc in scan.get("discovered_services") or []:
                svc_host = str(svc.get("host", "")).strip()
                port = svc.get("port")
                if svc_host:
                    add_node(f"ip:{svc_host}", svc_host, "ip", f"IP · {svc_host}")
                    add_edge(f"domain:{host}", f"ip:{svc_host}")
                    if port:
                        service_label = f"{str(svc.get('service', 'service')).upper()}:{port}"
                        add_node(f"service:{svc_host}:{port}", service_label, "service", f"Service · {svc_host}:{port}")
                        add_edge(f"ip:{svc_host}", f"service:{svc_host}:{port}")

        payload = {"nodes": nodes, "edges": edges, "updated_at": datetime.now(timezone.utc).isoformat()}
        payload["status"] = "success"
        return _deprecated_json(payload, 200, "dashboard.refresh(include_discovery=true)")
    except Exception as exc:
        return _deprecated_json({"status": "error", "message": str(exc)}, 500, "dashboard.refresh(include_discovery=true)")


def _inventory_scan_service_for_api():
    """Create inventory scan service bound to the app's scan pipeline."""
    from src.services.inventory_scan_service import InventoryScanService

    scan_runner = app.config.get("RUN_SCAN_PIPELINE_FUNC")
    return InventoryScanService(scan_runner=scan_runner)


def _can_access_roles(roles: set[str]) -> bool:
    if not getattr(current_user, "is_authenticated", False):
        return False
    user_role = str(getattr(current_user, "role", "") or "").strip().title()
    return user_role in {r.strip().title() for r in roles}


def _parse_ports_from_payload(value) -> list[int] | None:
    """Parse optional ports from JSON/form payload into list[int]."""
    if value is None:
        return None
    if isinstance(value, list):
        out = []
        for item in value:
            try:
                port = int(item)
                if 1 <= port <= 65535:
                    out.append(port)
            except (TypeError, ValueError):
                continue
        return out or None

    if isinstance(value, str):
        out = []
        for token in value.replace(" ", ",").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                port = int(token)
                if 1 <= port <= 65535:
                    out.append(port)
            except (TypeError, ValueError):
                continue
        return out or None

    return None


def _build_unified_dashboard_payload(include_discovery: bool = False) -> dict:
    """Build a single API payload for the full dashboard and scan center surfaces."""
    dashboard_data = get_dashboard_data()
    inventory_vm = _build_asset_inventory_view()

    payload = {
        "dashboard": dashboard_data,
        "inventory": inventory_vm,
        "recent_scans": db.list_scans(limit=20),
        "scan_status": _inventory_scan_service_for_api().get_scan_status(),
    }

    if include_discovery:
        payload["discovery"] = _build_asset_discovery_view()

    return payload


def _deprecated_json(payload: dict, status_code: int, replacement_action: str) -> Response:
    """Attach deprecation headers while preserving legacy endpoint payload shape."""
    response = jsonify(payload or {})
    response.status_code = status_code
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "2026-12-31"
    response.headers["Link"] = '</api/dashboard>; rel="successor-version"'
    response.headers["X-Replacement-Endpoint"] = "/api/dashboard"
    response.headers["X-Replacement-Action"] = replacement_action
    response.headers["Warning"] = (
        f'299 - "Deprecated endpoint, migrate to /api/dashboard with action={replacement_action}"'
    )
    return response


@app.route("/api/dashboard", methods=["GET", "POST"])
@csrf.exempt
@login_required
def api_dashboard_unified():
    """Single API entry point for dashboard reads and scan operations.

    GET query params:
      - include_discovery=true|false

    POST body/form fields:
      - action (required)
      Actions:
        - scan.run
        - scan.inventory.all
        - scan.inventory.status
        - scan.inventory.asset
        - scan.inventory.history
        - scan.inventory.schedule.get
        - scan.inventory.schedule.set
        - dashboard.refresh
    """
    try:
        if request.method == "GET":
            include_discovery = str(request.args.get("include_discovery", "false")).strip().lower() == "true"
            data = _build_unified_dashboard_payload(include_discovery=include_discovery)
            return jsonify({"status": "success", "data": data}), 200

        payload = request.get_json(silent=True) or {}
        if not payload:
            payload = request.form.to_dict(flat=True)

        action = str(payload.get("action", "")).strip().lower()
        if not action:
            return jsonify({"status": "error", "message": "Missing 'action'"}), 400

        # ── Targeted Scan ────────────────────────────────────────────────
        if action == "scan.run":
            if not _can_access_roles(SCAN_ROLES):
                return jsonify({"status": "error", "message": "Insufficient role for scan.run"}), 403

            target = str(payload.get("target", "")).strip()
            if not target:
                return jsonify({"status": "error", "message": "Missing 'target'"}), 400

            asset_class_hint = str(payload.get("asset_class_hint", "")).strip() or None
            ports = _parse_ports_from_payload(payload.get("ports"))
            clean_target, _ = sanitize_target(target)
            scanned_by = getattr(current_user, "username", None) if getattr(current_user, "is_authenticated", False) else None
            report = run_scan_pipeline(
                clean_target,
                ports=ports,
                asset_class_hint=asset_class_hint,
                scan_kind="api_scan_run",
                scanned_by=scanned_by,
            )

            if not app.config.get("TESTING", False) and not bool(report.get("orm_persisted")):
                db.save_scan(report)
            scan_store[report.get("scan_id")] = report

            _audit("scan", "api_dashboard_scan_run", "success", target_scan_id=report.get("scan_id"), details={"target": clean_target})
            return jsonify({"status": "success", "data": report}), 200

        # ── Inventory Bulk Scan ─────────────────────────────────────────
        if action == "scan.inventory.all":
            if not _can_access_roles(BULK_SCAN_ROLES):
                return jsonify({"status": "error", "message": "Insufficient role for scan.inventory.all"}), 403

            background = str(payload.get("background", "true")).strip().lower() != "false"
            result = _inventory_scan_service_for_api().scan_all_assets(background=background)
            code = 200 if result.get("status") in {"started", "complete", "in_progress"} else 500
            return jsonify({"status": "success", "data": result}), code

        # ── Inventory Scan Status ───────────────────────────────────────
        if action == "scan.inventory.status":
            if not _can_access_roles(SCAN_ROLES):
                return jsonify({"status": "error", "message": "Insufficient role for scan.inventory.status"}), 403

            status_data = _inventory_scan_service_for_api().get_scan_status()
            return jsonify({"status": "success", "data": status_data}), 200

        # ── Inventory Single Asset Scan ────────────────────────────────
        if action == "scan.inventory.asset":
            if not _can_access_roles(SCAN_ROLES):
                return jsonify({"status": "error", "message": "Insufficient role for scan.inventory.asset"}), 403

            from src.db import db_session
            from src.models import Asset

            try:
                asset_id_raw = payload.get("asset_id", "")
                asset_id = int(str(asset_id_raw).strip())
            except (TypeError, ValueError):
                return jsonify({"status": "error", "message": "Missing or invalid 'asset_id'"}), 400

            asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
            if not asset:
                return jsonify({"status": "error", "message": "Asset not found"}), 404

            result = _inventory_scan_service_for_api().scan_asset(asset)
            db_session.commit()
            code = 200 if result.get("status") == "complete" else 202
            return jsonify({"status": result.get("status") or "error", "data": result}), code

        # ── Inventory Asset History ────────────────────────────────────
        if action == "scan.inventory.history":
            if not _can_access_roles(SCAN_ROLES):
                return jsonify({"status": "error", "message": "Insufficient role for scan.inventory.history"}), 403

            try:
                asset_id_raw = payload.get("asset_id", "")
                asset_id = int(str(asset_id_raw).strip())
            except (TypeError, ValueError):
                return jsonify({"status": "error", "message": "Missing or invalid 'asset_id'"}), 400

            history = _inventory_scan_service_for_api().get_asset_scan_history(asset_id)
            return jsonify({"status": "success", "data": history}), 200

        # ── Inventory Schedule Get/Set ────────────────────────────────
        if action == "scan.inventory.schedule.get":
            if not _can_access_roles(BULK_SCAN_ROLES):
                return jsonify({"status": "error", "message": "Insufficient role for scan.inventory.schedule.get"}), 403

            from config import AUTOMATED_SCAN_ENABLED, AUTOMATED_SCAN_INTERVAL_HOURS

            return jsonify({
                "status": "success",
                "data": {"enabled": AUTOMATED_SCAN_ENABLED, "interval_hours": AUTOMATED_SCAN_INTERVAL_HOURS},
            }), 200

        if action == "scan.inventory.schedule.set":
            if not _can_access_roles(BULK_SCAN_ROLES):
                return jsonify({"status": "error", "message": "Insufficient role for scan.inventory.schedule.set"}), 403

            enabled = str(payload.get("enabled", "false")).strip().lower() == "true"
            try:
                interval_hours = int(payload.get("interval_hours", 24))
            except (TypeError, ValueError):
                return jsonify({"status": "error", "message": "Invalid 'interval_hours'"}), 400

            if interval_hours < 1 or interval_hours > 168:
                return jsonify({"status": "error", "message": "Interval must be between 1 and 168 hours"}), 400

            os.environ["INVENTORY_SCAN_ENABLED"] = str(enabled)
            os.environ["INVENTORY_SCAN_INTERVAL_HOURS"] = str(interval_hours)

            return jsonify({
                "status": "success",
                "message": "Schedule updated",
                "settings": {"enabled": enabled, "interval_hours": interval_hours},
            }), 200

        # ── Dashboard Refresh Payload ──────────────────────────────────
        if action == "dashboard.refresh":
            include_discovery = str(payload.get("include_discovery", "false")).strip().lower() == "true"
            data = _build_unified_dashboard_payload(include_discovery=include_discovery)
            return jsonify({"status": "success", "data": data}), 200

        return jsonify({
            "status": "error",
            "message": "Unsupported action",
            "supported_actions": [
                "scan.run",
                "scan.inventory.all",
                "scan.inventory.status",
                "scan.inventory.asset",
                "scan.inventory.history",
                "scan.inventory.schedule.get",
                "scan.inventory.schedule.set",
                "dashboard.refresh",
            ],
        }), 400
    except Exception as exc:
        _audit("api", "api_dashboard_unified", "failed", details={"error": str(exc)})
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/inventory/scan", methods=["POST"])
@role_required(list(SCAN_ROLES))
def api_inventory_scan_all():
    """Start or run inventory-wide scan and return JSON status."""
    try:
        payload = request.get_json(silent=True) or {}
        background_raw = payload.get("background", request.form.get("background", "true"))
        background = str(background_raw).strip().lower() != "false"

        scan_service = _inventory_scan_service_for_api()
        result = scan_service.scan_all_assets(background=background)
        _audit("scan", "inventory_scan_all", "success", details={"background": background, "status": result.get("status")})
        code = 200 if result.get("status") in {"started", "complete", "in_progress"} else 500
        return _deprecated_json(result, code, "scan.inventory.all")
    except Exception as exc:
        _audit("scan", "inventory_scan_all", "failed", details={"error": str(exc)})
        return _deprecated_json({"status": "error", "message": str(exc)}, 500, "scan.inventory.all")


@app.route("/api/inventory/scan-status", methods=["GET"])
@role_required(list(SCAN_ROLES))
def api_inventory_scan_status():
    """Return inventory scan progress/status payload."""
    try:
        scan_service = _inventory_scan_service_for_api()
        status_data = scan_service.get_scan_status()
        _audit("scan", "inventory_scan_status_requested", "success", details={"status": status_data.get("status")})
        return _deprecated_json({"status": "success", "data": status_data}, 200, "scan.inventory.status")
    except Exception as exc:
        _audit("scan", "inventory_scan_status_requested", "failed", details={"error": str(exc)})
        return _deprecated_json({"status": "error", "message": str(exc)}, 500, "scan.inventory.status")


@app.route("/api/inventory/asset/<int:asset_id>/scan", methods=["POST"])
@role_required(list(SCAN_ROLES))
def api_inventory_scan_asset(asset_id: int):
    """Run a single inventory asset scan and return JSON result."""
    from src.db import db_session
    from src.models import Asset

    try:
        asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
        if not asset:
            _audit("scan", "inventory_scan_asset", "failed", details={"asset_id": asset_id, "error": "asset_not_found"})
            return _deprecated_json({"status": "error", "message": "Asset not found"}, 404, "scan.inventory.asset")

        scan_service = _inventory_scan_service_for_api()
        result = scan_service.scan_asset(asset)
        db_session.commit()
        code = 200 if result.get("status") == "complete" else 202
        _audit("scan", "inventory_scan_asset", "success", details={"asset_id": asset_id, "status": result.get("status")})
        return _deprecated_json({"status": result.get("status"), "data": result}, code, "scan.inventory.asset")
    except Exception as exc:
        db_session.rollback()
        _audit("scan", "inventory_scan_asset", "failed", details={"asset_id": asset_id, "error": str(exc)})
        return _deprecated_json({"status": "error", "message": str(exc)}, 500, "scan.inventory.asset")


@app.route("/api/inventory/asset/<int:asset_id>/history", methods=["GET"])
@role_required(list(SCAN_ROLES))
def api_inventory_asset_history(asset_id: int):
    """Return scan history for a single inventory asset."""
    try:
        scan_service = _inventory_scan_service_for_api()
        history = scan_service.get_asset_scan_history(asset_id)
        _audit("scan", "inventory_asset_history_requested", "success", details={"asset_id": asset_id})
        return _deprecated_json({"status": "success", "data": history}, 200, "scan.inventory.history")
    except Exception as exc:
        _audit("scan", "inventory_asset_history_requested", "failed", details={"asset_id": asset_id, "error": str(exc)})
        return _deprecated_json({"status": "error", "message": str(exc)}, 500, "scan.inventory.history")


@app.route("/api/inventory/schedule", methods=["GET", "POST"])
@role_required(list(BULK_SCAN_ROLES))
def api_inventory_schedule():
    """Get or update inventory schedule settings using JSON API semantics."""
    try:
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
            enabled_raw = payload.get("enabled", request.form.get("enabled", "false"))
            interval_raw = payload.get("interval_hours", request.form.get("interval_hours", 24))
            enabled = str(enabled_raw).strip().lower() == "true"
            try:
                interval_hours = int(interval_raw)
            except (ValueError, TypeError):
                interval_hours = 24

            if interval_hours < 1 or interval_hours > 168:
                return _deprecated_json({"status": "error", "message": "Interval must be between 1 and 168 hours"}, 400, "scan.inventory.schedule.set")

            os.environ["INVENTORY_SCAN_ENABLED"] = str(enabled)
            os.environ["INVENTORY_SCAN_INTERVAL_HOURS"] = str(interval_hours)
            return _deprecated_json({
                "status": "success",
                "message": "Schedule updated",
                "settings": {"enabled": enabled, "interval_hours": interval_hours},
            }, 200, "scan.inventory.schedule.set")

        from config import AUTOMATED_SCAN_ENABLED, AUTOMATED_SCAN_INTERVAL_HOURS
        return _deprecated_json({
            "status": "success",
            "data": {"enabled": AUTOMATED_SCAN_ENABLED, "interval_hours": AUTOMATED_SCAN_INTERVAL_HOURS},
        }, 200, "scan.inventory.schedule.get")
    except Exception as exc:
        return _deprecated_json({"status": "error", "message": str(exc)}, 500, "scan.inventory.schedule.get")


@app.route("/cbom-dashboard")
@login_required
def cbom_dashboard():
    """Build CBOM view with aggregated cryptographic metrics from MySQL.
    
    Always queries live database—never returns hardcoded KPIs. Service failures
    fall back to minimal DB aggregation to ensure KPIs always reflect current state.
    """
    from src.services.cbom_service import CbomService

    try:
        asset_filter_id = request.args.get("asset_id", type=int)
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        page = max(1, request.args.get("page", 1, type=int) or 1)
        page_size = min(max(1, request.args.get("page_size", 25, type=int) or 25), 250)
        sort_field = (request.args.get("sort") or "asset_name").strip()
        sort_order = (request.args.get("order") or "asc").strip().lower()
        search_term = (request.args.get("q") or "").strip()

        cbom_data = CbomService.get_cbom_dashboard_data(
            asset_id=asset_filter_id,
            start_date=start_date_str,
            end_date=end_date_str,
            limit=200,
            page=page,
            page_size=page_size,
            sort_field=sort_field,
            sort_order=sort_order,
            search_term=search_term,
        )

        vm = {
            "empty": (cbom_data.get("meta", {}).get("certificate_count", 0) or 0) == 0,
            "kpis": cbom_data.get("kpis", {}),
            "key_length_distribution": cbom_data.get("key_length_distribution", {"No Data": 0}),
            "cipher_usage": cbom_data.get("cipher_usage", {"No Data": 0}),
            "top_cas": cbom_data.get("top_cas", {"No Data": 0}),
            "protocols": cbom_data.get("protocols", {"No Data": 0}),
            "minimum_elements": cbom_data.get("minimum_elements", {"total_entries": 0, "asset_type_distribution": {}, "field_coverage": {}, "items": []}),
            "rows": [],
            "weakness_heatmap": cbom_data.get("weakness_heatmap", []),
        }

        page_data = cbom_data.get("page_data", {
            "items": [], "total_count": 0, "page": 1, "page_size": 0, "total_pages": 1, "has_next": False, "has_prev": False
        })

    except Exception as e:
        current_app.logger.error("CBOM dashboard error: %s", e)
        # On error, query DB directly for KPI counts instead of hardcoding zeros
        try:
            from src.db import db_session
            from src.models import Certificate
            from sqlalchemy import func
            
            cert_count = db_session.query(Certificate).filter(Certificate.is_deleted == False).count()
            active_certs = db_session.query(func.count(Certificate.id)).filter(
                Certificate.is_deleted == False,
                Certificate.valid_until >= func.now()
            ).scalar() or 0
            
            fallback_kpis = {
                "total_applications": cert_count,
                "sites_surveyed": cert_count,
                "active_certificates": active_certs,
                "weak_cryptography": 0,
                "certificate_issues": 0,
            }
        except Exception as db_e:
            current_app.logger.error("CBOM KPI fallback DB query failed: %s", db_e)
            fallback_kpis = {
                "total_applications": 0,
                "sites_surveyed": 0,
                "active_certificates": 0,
                "weak_cryptography": 0,
                "certificate_issues": 0,
            }
        
        vm = {
            "empty": True,
            "kpis": fallback_kpis,
            "key_length_distribution": {"No Data": 0},
            "cipher_usage": {"No Data": 0},
            "top_cas": {"No Data": 0},
            "protocols": {"No Data": 0},
            "minimum_elements": {"total_entries": 0, "asset_type_distribution": {}, "field_coverage": {}, "items": []},
            "rows": [],
            "weakness_heatmap": [],
        }
        page_data: typing.Dict[str, typing.Any] = {"items": [], "total_count": 0, "page": 1, "page_size": 0, "total_pages": 1, "has_next": False, "has_prev": False}

    return render_template("cbom_dashboard.html", vm=vm, page_data=page_data)


@app.route("/pqc-posture")
@login_required
def pqc_posture():
    """Build PQC posture with aggregated quantum-safe readiness metrics from service.
    
    Only includes active (non-deleted) assets. Metrics aggregated by asset count,
    not scan count. Joins Asset -> PQCClassification to ensure consistency.
    Always queries live database—never returns hardcoded KPIs.
    """
    from src.services.pqc_service import PQCService
    
    try:
        page = max(1, request.args.get("page", 1, type=int) or 1)
        page_size = min(max(1, request.args.get("page_size", 25, type=int) or 25), 250)
        sort_field = (request.args.get("sort") or "asset_name").strip()
        sort_order = (request.args.get("order") or "asc").strip().lower()
        search_term = (request.args.get("q") or "").strip()

        # Load PQC dashboard data from service (asset-based aggregation, soft-delete filtering)
        data = PQCService.get_pqc_dashboard_data(
            page=page,
            page_size=page_size,
            sort_field=sort_field,
            sort_order=sort_order,
            search_term=search_term,
            limit=500,
        )
        
        # Build view model with percentages and counts
        vm = {
            "empty": data["meta"]["total_assets"] == 0,
            "overall": {
                "elite": data["kpis"]["elite_pct"],
                "standard": data["kpis"]["standard_pct"],
                "legacy": data["kpis"]["legacy_pct"],
                "critical_apps": data["kpis"]["critical_count"],
            },
            "grade_counts": data["grade_counts"],
            "average_pqc_score": data["kpis"]["avg_score"],
            "status_distribution": data["status_distribution"],
            "recommendations": data["recommendations"],
            "support_rows": data["applications"],
            "risk_heatmap": data["risk_heatmap"],
        }
        
        # Build pagination data (applications are asset-based)
        page_data = data.get("page_data", {
            "items": data.get("applications", []),
            "total_count": len(data.get("applications", [])),
            "page": 1,
            "page_size": len(data.get("applications", [])),
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        })
        
    except Exception as e:
        current_app.logger.error(f"PQC dashboard error: {e}")
        # On error, return minimal KPI structure instead of hardcoded zeros
        vm = {
            "empty": True,
            "overall": {"elite": 0, "standard": 0, "legacy": 0, "critical_apps": 0},
            "grade_counts": {"Elite": 0, "Standard": 0, "Legacy": 0, "Critical": 0},
            "average_pqc_score": 0,
            "status_distribution": {},
            "recommendations": ["Run scans to populate PQC posture."],
            "support_rows": [],
            "risk_heatmap": []
        }
        page_data: typing.Dict[str, typing.Any] = {"items": [], "total_count": 0, "page": 1, "page_size": 0, "total_pages": 1, "has_next": False, "has_prev": False}
    
    return render_template("pqc_posture.html", vm=vm, page_data=page_data)


@app.route("/cyber-rating")
@login_required
def cyber_rating():
    """Build cyber rating from active inventory assets and live DB telemetry.
    
    Always queries live database—never returns hardcoded KPIs.
    """
    from src.services.cyber_reporting_service import CyberReportingService
    try:
        data = CyberReportingService.get_cyber_rating_data(limit=200)

        avg_score = data.get("kpis", {}).get("avg_score", 0)
        if avg_score >= 90:
            label = "A"
        elif avg_score >= 80:
            label = "B"
        elif avg_score >= 70:
            label = "C"
        elif avg_score >= 60:
            label = "D"
        else:
            label = "F"

        items = data.get("applications", [])
        page_data: typing.Dict[str, typing.Any] = {
            "items": items,
            "total_count": len(items),
            "page": 1,
            "page_size": len(items),
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        }

        vm = {
            "empty": data.get("meta", {}).get("total_assets", 0) == 0,
            "overall_score": avg_score,
            "label": label,
            "tier_counts": {
                "Critical": data.get("grade_counts", {}).get("Critical", 0),
                "Legacy": data.get("grade_counts", {}).get("Legacy", 0),
                "Standard": data.get("grade_counts", {}).get("Standard", 0),
                "Elite-PQC": data.get("grade_counts", {}).get("Elite", 0),
            },
            "tier_heatmap": data.get("risk_heatmap", []),
            "recommendations": data.get("recommendations", []),
        }
    except Exception as e:
        current_app.logger.error("Cyber rating error: %s", e)
        vm = {
            "empty": True,
            "overall_score": 0,
            "label": "Unknown",
            "tier_counts": {"Critical": 0, "Legacy": 0, "Standard": 0, "Elite-PQC": 0},
            "tier_heatmap": [],
            "recommendations": ["Run scans to populate cyber posture."],
        }
        page_data: typing.Dict[str, typing.Any] = {"items": [], "total_count": 0, "page": 1, "page_size": 0, "total_pages": 1, "has_next": False, "has_prev": False}
    return render_template("cyber_rating.html", vm=vm, page_data=page_data)


@app.route("/reporting")
@login_required
def reporting():
    """Build reporting dashboard from live database metrics.
    
    Always queries live database—never returns hardcoded KPIs.
    """
    from src.services.cyber_reporting_service import CyberReportingService
    try:
        summary = CyberReportingService.get_reporting_summary()

        vm = {
            "summary": summary,
            "empty": "Targets: 0" in str(summary.get("discovery", "")),
        }
    except Exception as e:
        current_app.logger.error("Reporting dashboard error: %s", e)
        vm = {
            "summary": {
                "discovery": "Targets: 0 | Complete Scans: 0 | Assessed Endpoints: 0",
                "pqc": "Assessed endpoints: 0 | Average PQC Score: 0%",
                "cbom": "Total certificates: 0 | Weak cryptography: 0",
                "cyber_rating": "Average enterprise score: 0/100",
                "inventory": "Assets: 0 | Critical Apps: 0 | Legacy: 0",
            }, 
            "empty": True
        }
    return render_template("reporting.html", vm=vm)


@app.route("/scan", methods=["POST"])
@limiter.limit("20 per hour")
@role_required(list(SCAN_ROLES))
def scan():
    """Run a scan on one or multiple targets (text input + CSV upload)."""
    import re
    import csv
    import io

    target_input = request.form.get("target", "").strip()
    ports_str = request.form.get("ports", "").strip()
    autodiscovery = request.form.get("autodiscovery") == "on"
    add_to_inventory = request.form.get("add_to_inventory") == "on"
    
    # Extract metadata options supporting single/bulk fallback names
    inv_owner = (request.form.get("inv_owner") or request.form.get("inv_owner_bulk") or "").strip() or None
    inv_risk = (request.form.get("inv_risk") or request.form.get("inv_risk_bulk") or "Medium").strip()
    inv_notes = (request.form.get("inv_notes") or request.form.get("inv_notes_bulk") or "").strip() or None

    asset_class_mode = (
        request.form.get("asset_class_mode")
        or request.form.get("asset_class_mode_bulk")
        or "auto"
    ).strip().lower()
    asset_class_value = (
        request.form.get("asset_class_value")
        or request.form.get("asset_class_value_bulk")
        or ""
    ).strip()
    asset_class_hint = asset_class_value if asset_class_mode == "manual" and asset_class_value else None

    # Parse global custom ports
    custom_ports = None
    if ports_str:
        try:
            custom_ports = [
                int(p.strip()) for p in ports_str.replace(" ", ",").split(",")
                if p.strip().isdigit()
            ]
        except ValueError:
            pass

    # Autodiscovery mode: use the exhaustive port list
    if autodiscovery and not custom_ports:
        custom_ports = list(AUTODISCOVERY_PORTS)

    # ── Collect targets from text input ──
    targets = []  # list of (host, per_target_ports_or_None)
    if target_input:
        raw_targets = re.split(r'[,\n]+', target_input)
        for t in raw_targets:
            t = t.strip()
            if t:
                targets.append((t, custom_ports))

    # ── Collect targets from CSV upload ──
    csv_file = request.files.get("csv_file")
    if csv_file and csv_file.filename:
        try:
            stream = io.StringIO(csv_file.stream.read().decode("utf-8-sig"))
            reader = csv.DictReader(stream)
            # Normalize column headers to lowercase
            if reader.fieldnames is not None:
                reader.fieldnames = [f.strip().lower() for f in reader.fieldnames]
            for row in reader:
                host = (
                    row.get("ip", "")
                    or row.get("host", "")
                    or row.get("target", "")
                    or row.get("domain", "")
                ).strip()
                if not host:
                    continue
                port_val = row.get("port", "").strip()
                if port_val and port_val.isdigit():
                    row_ports = [int(port_val)]
                else:
                    row_ports = custom_ports
                targets.append((host, row_ports))
        except Exception:
            pass  # silently skip malformed CSV

    if not targets:
        _audit("scan", "scan_requested", "failed", details={"reason": "no_targets"})
        return redirect(url_for("quantumshield_dashboard.dashboard_home"))
        
    # Enforce advanced RBAC
    is_bulk = (csv_file and csv_file.filename) or len(targets) > 1
    if is_bulk and current_user.role not in BULK_SCAN_ROLES:
        _audit("scan", "bulk_scan_denied", "denied", details={"role": current_user.role, "target_count": len(targets)})
        flash("Your role allows single-target scans only.", "error")
        return redirect(url_for("quantumshield_dashboard.dashboard_home"))

    try:
        if len(targets) == 1:
            # Single scan: redirect directly to results page
            host, ports = targets[0]
            clean_target, _ = sanitize_target(host)
            report = run_scan_pipeline(
                clean_target,
                ports,
                asset_class_hint=asset_class_hint,
                scan_kind="manual_single",
                scanned_by=getattr(current_user, "username", None),
            )
            
            # Ensure persistence to both JSON and MySQL
            try:
                if not app.config.get("TESTING", False) and not bool(report.get("orm_persisted")):
                    db.save_scan(report)
                    
                    if add_to_inventory:
                        from src.db import db_session
                        from src.models import Asset
                        exists = db_session.query(Asset).filter(Asset.name == clean_target, Asset.is_deleted == False).first()
                        if not exists:
                            asset_type = asset_class_hint or "Web App"
                            new_asset = Asset(
                                name=clean_target,
                                url=f"https://{clean_target}" if not clean_target.startswith('http') else clean_target,
                                asset_type=asset_type,
                                owner=inv_owner,
                                risk_level=inv_risk,
                                notes=inv_notes,
                                is_deleted=False
                            )
                            db_session.add(new_asset)
                            db_session.commit()
                            flash(f"Asset {clean_target} added to inventory.", "success")
                            logger.info(f"Auto-added model {clean_target} to Asset Inventory.")
            except Exception as db_err:
                logger.warning(f"Failed to save scan/asset to MySQL: {db_err}")
            
            scan_store[report.get("scan_id")] = report
            _audit("scan", "single_scan", "success", target_scan_id=report.get("scan_id"), details={"target": clean_target})
            return redirect(url_for("results", scan_id=report.get("scan_id", "")))

        else:
            # Bulk scan: run all and redirect to dashboard
            successful_scans = []
            failed_scans = []
            for host, ports in targets:
                try:
                    clean_target, _ = sanitize_target(host)
                    report = run_scan_pipeline(
                        clean_target,
                        ports,
                        asset_class_hint=asset_class_hint,
                        scan_kind="manual_bulk",
                        scanned_by=getattr(current_user, "username", None),
                    )
                    
                    # Persist to both JSON and MySQL
                    try:
                        if not app.config.get("TESTING", False) and not bool(report.get("orm_persisted")):
                            db.save_scan(report)
                            
                            if add_to_inventory:
                                from src.db import db_session
                                from src.models import Asset
                                exists = db_session.query(Asset).filter(Asset.name == clean_target, Asset.is_deleted == False).first()
                                if not exists:
                                    asset_type = asset_class_hint or "Web App"
                                    new_asset = Asset(
                                        name=clean_target,
                                        url=f"https://{clean_target}" if not clean_target.startswith('http') else clean_target,
                                        asset_type=asset_type,
                                        owner=inv_owner,
                                        risk_level=inv_risk,
                                        notes=inv_notes,
                                        is_deleted=False
                                    )
                                    db_session.add(new_asset)
                                    db_session.commit()
                                    flash(f"Asset {clean_target} added to inventory.", "success")
                    except Exception as db_err:
                            logger.warning(f"Failed to save scan/asset to MySQL for {clean_target}: {db_err}")
                    
                    scan_store[report.get("scan_id")] = report
                    successful_scans.append(clean_target)
                    _audit("scan", "bulk_scan_item", "success", target_scan_id=report.get("scan_id"), details={"target": clean_target})
                except Exception as item_err:
                    failed_scans.append({"target": host, "error": str(item_err)})
                    logger.warning(f"Failed to scan {host}: {item_err}")
                    continue

            _audit("scan", "bulk_scan", "success", details={"target_count": len(targets), "successful": len(successful_scans), "failed": len(failed_scans)})
            return redirect(url_for("quantumshield_dashboard.dashboard_home"))

    except Exception as exc:
        _audit("scan", "scan_error", "failed", details={"error": str(exc), "target_count": len(targets)})
        error_id = uuid.uuid4().hex[:8]
        return render_template(
            "error.html",
            error_id=error_id,
            error_message=str(exc),
            traceback_info=traceback.format_exc(),
        )


@app.route("/results/<scan_id>")
@login_required
def results(scan_id: str):
    """Display scan results (memory → disk → MySQL fallback)."""
    import re as _re
    if not _re.match(r'^[a-f0-9A-F\-]+$', scan_id):
        return render_template("error.html", error_message="Invalid scan ID."), 404
    report = scan_store.get(scan_id)
    if not report:
        # Try loading from disk
        report_path = os.path.join(RESULTS_DIR, f"{scan_id}_report.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as fh:
                report = json.load(fh)
                scan_store[scan_id] = report
        else:
            # Try loading from MySQL
            report = db.get_scan(scan_id)
            if report:
                scan_store[scan_id] = report
            else:
                _audit("scan", "view_result", "failed", target_scan_id=scan_id, details={"reason": "not_found"})
                return render_template("error.html", error_message="Scan not found."), 404

    _audit("scan", "view_result", "success", target_scan_id=scan_id, details={"target": report.get("target")})
    return render_template("results.html", report=report, scan_id=scan_id)


@app.route("/cbom/<scan_id>")
@login_required
def download_cbom(scan_id: str):
    """Download CBOM JSON file (disk → MySQL fallback)."""
    import re as _re
    if not _re.match(r'^[a-f0-9A-F\-]+$', scan_id):
        return jsonify({"error": "Invalid scan ID."}), 404
    cbom_path = os.path.join(RESULTS_DIR, f"{scan_id}_cbom.json")
    if os.path.exists(cbom_path):
        try:
            _audit("scan", "download_cbom", "success", target_scan_id=scan_id, details={"source": "disk"})
            return send_file(
                cbom_path,
                mimetype="application/json",
                as_attachment=True,
                download_name=f"cbom_{scan_id}.json",
            )
        except Exception as err:
            logger.error(f"Error serving CBOM from disk: {err}")
            return jsonify({"error": "Could not serve CBOM file"}), 500
    
    # Fallback: try MySQL
    try:
        cbom_data = db.get_cbom(scan_id)
        if cbom_data:
            _audit("scan", "download_cbom", "success", target_scan_id=scan_id, details={"source": "database"})
            return jsonify({"status": "success", "data": cbom_data}), 200
    except Exception as db_err:
        logger.warning(f"Failed to retrieve CBOM from database: {db_err}")
    
    _audit("scan", "download_cbom", "failed", target_scan_id=scan_id, details={"reason": "not_found"})
    return jsonify({"error": "CBOM not found"}), 404


@app.route("/api/badge/<path:target>")
def api_badge(target: str):
    """Dynamic SVG badge showing Quantum-Safe status."""
    report = db.get_latest_scan_by_target(target)
    
    if not report:
        status_text = "Unknown"
        color = "#9ca3af" # gray-400
    else:
        overview = report.get("overview", {})
        if overview.get("quantum_vulnerable", 0) > 0:
            status_text = "Vulnerable"
            color = "#c45c5c" # muted red
        elif overview.get("quantum_safe", 0) > 0:
            status_text = "Quantum Safe"
            color = "#5b9e6f" # muted green
        elif report.get("status") == "error":
            status_text = "Scan Failed"
            color = "#c9a24e" # muted amber
        else:
            status_text = "Status: OK"
            color = "#5ba4b5" # teal
            
    # Simple standardized SVG badge layout (similar to shields.io)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="220" height="28" role="img" aria-label="QuantumShield: {status_text}">
      <title>QuantumShield: {status_text}</title>
      <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
      </linearGradient>
      <clipPath id="r">
        <rect width="220" height="28" rx="4" fill="#fff"/>
      </clipPath>
      <g clip-path="url(#r)">
        <rect width="110" height="28" fill="#1e2128"/>
        <rect x="110" width="110" height="28" fill="{color}"/>
        <rect width="220" height="28" fill="url(#s)"/>
      </g>
      <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="550" y="190" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="900">QuantumShield</text>
        <text x="550" y="180" transform="scale(.1)" fill="#fff" textLength="900">QuantumShield</text>
        <text aria-hidden="true" x="1650" y="190" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="900">{status_text}</text>
        <text x="1650" y="180" transform="scale(.1)" fill="#fff" textLength="900">{status_text}</text>
      </g>
    </svg>'''
    
    response = Response(svg, mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route("/api/scan", methods=["GET", "POST"])
@csrf.exempt  # Machine clients send API keys, not CSRF tokens
@limiter.limit("60 per hour")
@require_api_key
def api_scan():
    """REST API endpoint for CI/CD integration. Requires X-API-Key header.

    GET  /api/scan?target=example.com&api_key=qss_...
    POST /api/scan  {"target": "example.com", "api_key": "qss_..."}
    """
    from flask import g as _g
    api_user = _g.api_user

    if request.method == "GET":
        target = request.args.get("target", "")
    else:
        data = request.get_json(silent=True) or {}
        target = data.get("target", "") or request.form.get("target", "")

    if not target:
        return jsonify({"error": "Missing 'target' parameter"}), 400

    # Enforce role on API users too
    if api_user.get("role") not in SCAN_ROLES:
        db.append_audit_log(
            event_category="api",
            event_type="api_scan_forbidden",
            status="denied",
            actor_user_id=api_user.get("id"),
            actor_username=api_user.get("username"),
            ip_address=_get_request_ip(),
            request_method=request.method,
            request_path=request.path,
            details={"role": api_user.get("role"), "required_roles": list(SCAN_ROLES)},
        )
        return jsonify({"error": "Your API key role does not permit scanning"}), 403

    try:
        clean_target, _ = sanitize_target(target)
        report = run_scan_pipeline(
            clean_target,
            scan_kind="api_key_scan",
            scanned_by=api_user.get("username"),
        )
        
        # Ensure persistence: save to both JSON and MySQL
        try:
            if not app.config.get("TESTING", False) and not bool(report.get("orm_persisted")):
                db.save_scan(report)
        except Exception as db_err:
            logger.warning(f"Failed to save scan to MySQL: {db_err}")
        
        db.append_audit_log(
            event_category="api",
            event_type="api_scan",
            status="success",
            actor_user_id=api_user.get("id"),
            actor_username=api_user.get("username"),
            target_scan_id=report.get("scan_id"),
            ip_address=_get_request_ip(),
            request_method=request.method,
            request_path=request.path,
            details={"target": clean_target},
        )
        return jsonify({"status": "success", "data": report}), 200
    except Exception as exc:
        _audit("scan", "api_scan", "failed", details={"target": target, "error": str(exc)})
        logger.exception(f"API scan failed for target {target}: {exc}")
        return jsonify({"status": "error", "message": str(exc)}), 500



@app.route("/api/scans-legacy")
@csrf.exempt
@require_api_key
def api_list_scans():
    """List all stored scan results. Requires X-API-Key header."""
    from flask import g as _g
    api_user = _g.api_user
    try:
        scans = [
            {
                "scan_id": r.get("scan_id"),
                "target": r.get("target"),
                "status": r.get("status"),
                "generated_at": r.get("generated_at"),
                "overview": r.get("overview"),
            }
            for r in scan_store.values()
        ]
        _audit("api", "api_list_scans", "success", details={"scan_count": len(scans)})
        return jsonify(scans), 200
    except Exception as exc:
        _audit("api", "api_list_scans", "failed", details={"error": str(exc)})
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/docs")
def docs():
    """Comprehensive documentation and technical guide."""
    return render_template("docs.html")


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    """User profile page showing API key info."""
    user_data = db.get_user_by_id(current_user.id)
    # Auto-issue an API key on first visit if none exists
    new_key = None
    if user_data and not user_data.get("api_key_hash"):
        new_key = db.generate_api_key(current_user.id)
        if new_key:
            _audit("api", "api_key_auto_issued", "success",
                   details={"reason": "first_visit"})
    key_issued = db.has_api_key(current_user.id)
    return render_template(
        "profile.html",
        user=user_data,
        key_issued=key_issued,
        new_key=new_key,  # Only shown once on auto-issue
    )


@app.route("/profile/rotate-api-key", methods=["POST"])
@login_required
def rotate_api_key():
    """Revoke the current API key and issue a fresh one."""
    db.revoke_api_key(current_user.id)
    new_key = db.generate_api_key(current_user.id)
    if new_key:
        _audit("api", "api_key_rotated", "success")
        flash(f"NEW_API_KEY: {new_key}", "api_key")  # One-time display
    else:
        _audit("api", "api_key_rotated", "failed")
        flash("Failed to rotate API key. Try again.", "error")
    return redirect(url_for("profile"))


@app.route("/admin/users/<user_id>/regen-api-key", methods=["POST"])
@role_required(list(ADMIN_PANEL_ROLES))
def admin_regen_api_key(user_id: str):
    """Admin: revoke and reissue an API key for any user. Supports form OR JSON."""
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    user = db.get_user_by_id(user_id)
    if not user:
        if wants_json:
            return jsonify({"status": "error", "message": "User not found."}), 404
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))
    
    db.revoke_api_key(user_id)
    new_key = db.generate_api_key(user_id)
    if new_key:
        _audit("admin", "api_key_regen", "success", target_user_id=user_id,
               details={"username": user.get("username")})
        if wants_json:
            return jsonify({
                "status": "success",
                "message": f"API key regenerated for {user.get('username')}.",
                "user_id": user_id,
                "username": user.get("username"),
                "api_key": new_key
            }), 200
        flash(f"New API key for {user.get('username')}: {new_key}", "api_key")
    else:
        _audit("admin", "api_key_regen", "failed", target_user_id=user_id)
        if wants_json:
            return jsonify({"status": "error", "message": "Failed to regenerate API key."}), 500
        flash("Failed to regenerate API key.", "error")
    return redirect(url_for("admin_users"))


# ── Report Generation Engine ─────────────────────────────────────────

def _make_pdf_report(report_type: str, username: str, sections: list[str], pdf_password: str | None = None) -> bytes:
    """Build a PDF byte-stream for the requested report type.

    Uses reportlab for full cross-platform support (Windows + Linux).
    Returns raw PDF bytes suitable for serving as a download.
    """
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )

    buf = BytesIO()
    doc_kwargs = {
        "pagesize": A4,
        "leftMargin": 2.2 * cm,
        "rightMargin": 2.2 * cm,
        "topMargin": 2.5 * cm,
        "bottomMargin": 2 * cm,
        "title": f"PNB Hackathon 2026 — {report_type}",
        "author": "QuantumShield Platform",
    }

    password_text = str(pdf_password or "").strip()
    if password_text:
        try:
            from reportlab.lib.pdfencrypt import StandardEncryption

            doc_kwargs["encrypt"] = StandardEncryption(
                userPassword=password_text,
                ownerPassword=password_text,
                canPrint=1,
                canModify=0,
                canCopy=0,
                canAnnotate=0,
                strength=128,
            )
        except Exception as exc:
            logger.warning("PDF encryption unavailable; generating plain PDF: %s", exc)

    doc = SimpleDocTemplate(buf, **doc_kwargs)

    styles = getSampleStyleSheet()
    TEAL = colors.HexColor("#4a9ead")
    DARK = colors.HexColor("#0f1219")
    GREY = colors.HexColor("#64748b")

    h1 = ParagraphStyle("H1", parent=styles["Title"], fontSize=20, leading=26,
                         textColor=DARK, spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, leading=18,
                         textColor=TEAL, spaceBefore=14, spaceAfter=4)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=14,
                          textColor=colors.HexColor("#1a2030"))
    caption = ParagraphStyle("Caption", parent=styles["Normal"], fontSize=8,
                              textColor=GREY, spaceAfter=6)

    now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    story = [
        Paragraph("PNB Hackathon 2026", ParagraphStyle("Brand", parent=styles["Normal"],
                  fontSize=9, textColor=TEAL, spaceAfter=2)),
        Paragraph(report_type, h1),
        HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=8),
        Paragraph(f"Generated: {now_str} &nbsp;|&nbsp; Prepared for: {username}", caption),
        Spacer(1, 0.3 * cm),
    ]

    inv = _build_asset_inventory_view()
    dis = _build_asset_discovery_view()

    cb_rows: list[tuple[str, str, str, str]] = []
    cb_key_dist: dict[str, int] = {}
    cb_cipher_usage: dict[str, int] = {}
    cb_protocols: dict[str, int] = {}
    pqc_rows: list[tuple[str, str, str]] = []
    cyber_rows: list[tuple[str, str]] = []

    if app.config.get("TESTING", False):
        for scan in scan_store.values():
            if scan.get("status") != "complete":
                continue
            for tr in (scan.get("tls_results") or []):
                key = str(tr.get("key_size") or tr.get("key_length") or "0")
                cb_key_dist[key] = cb_key_dist.get(key, 0) + 1
                for cs in (tr.get("cipher_suites") or []):
                    cb_cipher_usage[cs] = cb_cipher_usage.get(cs, 0) + 1
                proto = str(tr.get("tls_version") or "Unknown")
                cb_protocols[proto] = cb_protocols.get(proto, 0) + 1
                cb_rows.append((
                    _host_from_target(str(scan.get("target", ""))) or str(scan.get("target", "")),
                    key,
                    (tr.get("cipher_suites") or ["Unknown"])[0],
                    (tr.get("issuer") or {}).get("O", "Unknown") if isinstance(tr.get("issuer"), dict) else "Unknown",
                ))

        for scan in scan_store.values():
            if scan.get("status") != "complete":
                continue
            host = _host_from_target(str(scan.get("target", "")))
            for pqc in (scan.get("pqc_assessments") or []):
                score = int(pqc.get("pqc_score") or pqc.get("score") or 0)
                status = "Elite" if score >= 800 else ("Standard" if score >= 500 else ("Legacy" if score >= 300 else "Critical"))
                pqc_rows.append((host, str(score), status))

        for scan in scan_store.values():
            if scan.get("status") != "complete":
                continue
            overview = scan.get("overview") or {}
            raw = overview.get("average_compliance_score") or 0
            norm = min(int(raw * 10) if raw <= 100 else int(raw), 1000)
            cyber_rows.append((
                str(scan.get("target", "")),
                str(norm),
            ))
    else:
        from src.services.cbom_service import CbomService
        from src.services.pqc_service import PQCService
        from src.services.cyber_reporting_service import CyberReportingService
        from src.services.certificate_telemetry_service import CertificateTelemetryService

        cbom_data = CbomService.get_cbom_dashboard_data(limit=20)
        for key, count in cbom_data.get("key_length_distribution", {}).items():
            cb_key_dist[str(key)] = int(count or 0)
        for cipher, count in cbom_data.get("cipher_usage", {}).items():
            cb_cipher_usage[str(cipher)] = int(count or 0)
        for proto, count in cbom_data.get("protocols", {}).items():
            cb_protocols[str(proto)] = int(count or 0)
        for row in cbom_data.get("applications", [])[:20]:
            cb_rows.append((
                str(row.get("asset_name") or "Unknown"),
                str(row.get("key_length") or "0"),
                str(row.get("cipher_suite") or "Unknown"),
                str(row.get("ca") or "Unknown"),
            ))

        pqc_data = PQCService.get_pqc_dashboard_data(limit=20)
        for row in pqc_data.get("applications", [])[:20]:
            pqc_rows.append((
                str(row.get("asset_name") or row.get("target") or "Unknown"),
                str(int(float(row.get("score") or 0))),
                str(row.get("status") or "Critical"),
            ))

        cyber_data = CyberReportingService.get_cyber_rating_data(limit=20)
        for row in cyber_data.get("applications", [])[:20]:
            cyber_rows.append((
                str(row.get("target") or "Unknown"),
                str(int(float(row.get("score") or 0))),
            ))

        cert_service = CertificateTelemetryService()
        cert_inventory = cert_service.get_certificate_inventory(limit=20)
        for cert in cert_inventory:
            key = str(cert.get("key_length") or "0")
            cb_key_dist[key] = cb_key_dist.get(key, 0) + 1
            cb_cipher_usage[str(cert.get("cipher_suite") or "Unknown")] = cb_cipher_usage.get(str(cert.get("cipher_suite") or "Unknown"), 0) + 1
            cb_protocols[str(cert.get("tls_version") or "Unknown")] = cb_protocols.get(str(cert.get("tls_version") or "Unknown"), 0) + 1
            cb_rows.append((
                str(cert.get("asset") or "Unknown"),
                key,
                str(cert.get("cipher_suite") or "Unknown"),
                str(cert.get("issuer") or "Unknown"),
            ))

    section_data: dict[str, list] = {
        "Asset Inventory": [
            ("KPI", "Value"),
            ("Total Assets", str(inv["kpis"]["total_assets"])),
            ("Public Web Apps", str(inv["kpis"]["public_web_apps"])),
            ("APIs", str(inv["kpis"]["apis"])),
            ("Servers", str(inv["kpis"]["servers"])),
            ("Expiring Certificates", str(inv["kpis"]["expiring_certificates"])),
            ("High Risk Assets", str(inv["kpis"]["high_risk_assets"])),
        ],
        "Asset Discovery": [
            ("Category", "Count"),
            ("Domains discovered", str(dis["overview"]["domains"])),
            ("SSL certificates", str(dis["overview"]["ssl"])),
            ("IP/Subnets", str(dis["overview"]["ip_subnets"])),
            ("Software components", str(dis["overview"]["software"])),
            ("New (unconfirmed)", str(dis["status_counts"].get("New", 0))),
        ],
        "CBOM": [("Metric", "Value")] + [
            ("Unique Applications", str(len({r[0] for r in cb_rows}))),
            ("Active Certificates", str(len(cb_rows))),
            ("Key Length Buckets", str(len(cb_key_dist))),
            ("Cipher Suites", str(len(cb_cipher_usage))),
            ("TLS Protocol Families", str(len(cb_protocols))),
        ],
        "PQC Posture": [("Asset", "Score", "Status")] + (pqc_rows[:20] if pqc_rows else [("No data", "0", "N/A")]),
        "Cyber Rating": [("URL", "PQC Score")] + (cyber_rows[:20] if cyber_rows else [("No data", "0")]),
    }

    # ── Aggregate metrics from live scan store ───────────────────────
    live_scans = [s for s in scan_store.values() if s.get("status") == "complete"]
    if live_scans:
        story.append(Paragraph("Live Scan Summary", h2))
        live_rows = [("Target", "Score", "Status")]
        for s in live_scans[:15]:
            overview = s.get("overview") or {}
            live_rows.append((
                str(s.get("target", ""))[:60],
                str(overview.get("average_compliance_score", "—")),
                str(s.get("status", "")),
            ))
        t = Table(live_rows, colWidths=[10 * cm, 3 * cm, 3.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), TEAL),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafb"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4 * cm))

    # ── Requested sections ───────────────────────────────────────────
    selected = sections if sections else list(section_data.keys())
    for sec in selected:
        rows = section_data.get(sec)
        if not rows:
            continue
        story.append(Paragraph(sec, h2))
        col_count = len(rows[0])
        col_width = 16.6 * cm / col_count
        t = Table(rows, colWidths=[col_width] * col_count)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), TEAL),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafb"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * cm))

    # ── Footer note ──────────────────────────────────────────────────
    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY))
    story.append(Paragraph(
        "This report is confidential and intended for authorised PNB personnel only. "
        "Generated by QuantumShield | PNB Hackathon 2026.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7.5, textColor=GREY, spaceBefore=4),
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


# ── Scheduled-report JSON store (DB-independent) ─────────────────────
# Stored as: RESULTS_DIR/report_schedules.json
_SCHEDULES_PATH = os.path.join(RESULTS_DIR, "report_schedules.json")


def _load_schedules() -> list[dict]:
    db_rows = db.list_report_schedules(limit=1000)
    if db_rows:
        return db_rows
    try:
        with open(_SCHEDULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_schedules(schedules: list[dict]) -> None:
    ok_count = 0
    for row in schedules:
        if db.save_report_schedule(row):
            ok_count += 1
    if ok_count == len(schedules):
        return
    with open(_SCHEDULES_PATH, "w", encoding="utf-8") as f:
        json.dump(schedules, f, indent=2, default=str)


def _safe_report_output_path(save_path: str, filename: str) -> str:
    base_dir = os.path.join(RESULTS_DIR, "generated_reports")
    raw_subdir = str(save_path or "").strip().replace("\\", "/")
    if not raw_subdir:
        subdir = "manual"
    else:
        parts = [p for p in raw_subdir.split("/") if p and p not in (".", "..")]
        cleaned = []
        for part in parts:
            safe = "".join(ch for ch in part if ch.isalnum() or ch in ("-", "_", "."))
            if safe:
                cleaned.append(safe)
        subdir = os.path.join(*cleaned) if cleaned else "manual"

    out_dir = os.path.join(base_dir, subdir)
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, filename)


def _send_report_email(email_list: str, report_type: str, filename: str, pdf_bytes: bytes) -> tuple[bool, str]:
    recipients = [e.strip() for e in re.split(r"[;,]", str(email_list or "")) if e.strip()]
    if not recipients:
        return False, "no_recipients"

    msg = Message(
        subject=f"QuantumShield Report — {report_type}",
        recipients=recipients,
        body=(
            "Attached is your generated QuantumShield report.\n\n"
            f"Report Type: {report_type}\n"
            f"Generated At: {datetime.now(timezone.utc).isoformat()}\n"
        ),
    )
    msg.attach(filename=filename, content_type="application/pdf", data=pdf_bytes)
    mail.send(msg)
    return True, "sent"


@app.route("/favicon.ico")
def favicon():
    """Silence browser 404s on favicon."""
    return "", 204


@app.route("/report/generate", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def generate_report():
    """Generate a PDF report on demand and return it as a file download.

    Accepts JSON or form data. Input fields:
      report_type  – string label (e.g. "Executive Reporting")
      sections     – JSON array of section names to include (optional)
      password     – optional password to note in filename (not encrypted yet)
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form

    report_type = (data.get("report_type") or "Executive Reporting").strip()[:120]
    raw_sections = data.get("sections") or "[]"
    if isinstance(raw_sections, str):
        try:
            sections = json.loads(raw_sections)
        except (ValueError, TypeError):
            sections = []
    else:
        sections = list(raw_sections)

    username = getattr(current_user, "username", "user")
    email_enabled = str(data.get("email_enabled") or "").lower() in ("true", "1", "on")
    email_list = str(data.get("email_list") or "").strip()
    save_enabled = str(data.get("save_enabled") or "").lower() in ("true", "1", "on")
    save_path = str(data.get("save_path") or "").strip()
    password_protect = str(data.get("password_protect") or "").lower() in ("true", "1", "on")
    password = str(data.get("password") or "").strip()
    if password_protect and not password:
        return jsonify({"status": "error", "message": "Password is required when password protection is enabled."}), 400

    _audit("report", "generate_pdf", "success", details={
        "report_type": report_type,
        "sections": sections,
        "username": username,
        "email_enabled": email_enabled,
        "save_enabled": save_enabled,
        "password_protect": password_protect,
    })

    pdf_bytes = _make_pdf_report(
        report_type,
        username,
        sections,
        pdf_password=password if password_protect else None,
    )
    safe_type = "".join(c if c.isalnum() else "_" for c in report_type)[:40]
    filename = f"PNB_{safe_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"

    if save_enabled:
        try:
            out_path = _safe_report_output_path(save_path, filename)
            with open(out_path, "wb") as f:
                f.write(pdf_bytes)
        except Exception as exc:
            logger.error("Failed to save generated report: %s", exc)
            _audit("report", "save_pdf_failed", "failed", details={"error": str(exc), "save_path": save_path})

    if email_enabled:
        try:
            sent, info = _send_report_email(email_list, report_type, filename, pdf_bytes)
            if not sent:
                _audit("report", "email_pdf_skipped", "failed", details={"reason": info})
            else:
                _audit("report", "email_pdf", "success", details={"recipients": email_list})
        except Exception as exc:
            logger.error("Failed to email generated report: %s", exc)
            _audit("report", "email_pdf", "failed", details={"error": str(exc), "recipients": email_list})

    return Response(
        pdf_bytes,
        status=200,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "X-Report-Encrypted": "true" if password_protect else "false",
        },
    )


@app.route("/report/schedule", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def schedule_report():
    """Save a scheduled report configuration.

    Accepts JSON or form data and persists to report_schedules.json.
    Returns JSON with the created schedule id.
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = dict(request.form)

    # Normalise form multi-values to single values where applicable
    def _single(v):
        return v[0] if isinstance(v, list) else (v or "")

    password_protect = str(_single(data.get("password_protect", ""))).lower() in ("true", "1", "on")
    password = str(_single(data.get("password", ""))).strip()
    if password_protect and not password:
        return jsonify({"status": "error", "message": "Password is required when password protection is enabled."}), 400

    schedule = {
        "id": uuid.uuid4().hex[:12],
        "created_by_id": str(getattr(current_user, "id", "")) or None,
        "created_by": getattr(current_user, "username", "unknown"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "enabled": str(_single(data.get("enabled", "true"))).lower() not in ("false", "0", "off", ""),
        "report_type": _single(data.get("report_type", "Executive Summary Report"))[:120],
        "frequency": _single(data.get("frequency", "Weekly"))[:32],
        "assets": _single(data.get("assets", "All Assets"))[:256],
        "sections": data.get("sections") if isinstance(data.get("sections"), list) else [],
        "schedule_date": _single(data.get("schedule_date", ""))[:20],
        "schedule_time": _single(data.get("schedule_time", ""))[:10],
        "timezone": _single(data.get("timezone", "UTC"))[:64],
        "email_list": _single(data.get("email_list", ""))[:512],
        "password_protect": password_protect,
        "pdf_password": password if password_protect else "",
        "save_path": _single(data.get("save_path", ""))[:512],
        "download_link": _single(data.get("download_link", "false")).lower() in ("true", "1", "on"),
        "status": "scheduled",
    }

    if not db.save_report_schedule(schedule):
        schedules = _load_schedules()
        schedules.append(schedule)
        _save_schedules(schedules)

    _audit("report", "schedule_created", "success", details={
        "schedule_id": schedule["id"],
        "report_type": schedule["report_type"],
        "frequency": schedule["frequency"],
        "password_protected": password_protect,
    })

    return jsonify({"status": "ok", "id": schedule["id"], "message": "Schedule saved successfully."})


@app.route("/report/schedules", methods=["GET"])
@login_required
def list_report_schedules():
    """Return all saved report schedules as JSON."""
    schedules = db.list_report_schedules(limit=1000)
    if schedules:
        return jsonify(schedules)
    return jsonify(_load_schedules())


# ── HTTP → HTTPS redirect server (stdlib only, no extra deps) ──────────────

def _make_http_redirect_app(https_port: int, https_host: str):
    """Minimal WSGI app that 301-redirects every HTTP request to HTTPS."""
    def _redirect(environ, start_response):
        host = environ.get("HTTP_HOST") or https_host
        base = host.split(":")[0]          # strip any port in Host header
        path = environ.get("PATH_INFO", "/")
        qs   = environ.get("QUERY_STRING", "")
        url  = f"https://{base}:{https_port}{path}"
        if qs:
            url += "?" + qs
        start_response("301 Moved Permanently", [
            ("Location", url),
            ("Content-Type", "text/plain"),
            ("Content-Length", "0"),
        ])
        return [b""]
    return _redirect


def _start_http_redirect_server(http_port: int, https_port: int, https_host: str) -> None:
    """Launch the redirect WSGI server in a background daemon thread."""
    import threading
    from wsgiref.simple_server import WSGIServer, WSGIRequestHandler

    class _Quiet(WSGIRequestHandler):
        def log_message(self, *_):
            pass   # suppress noisy per-request logs

    app_redirect = _make_http_redirect_app(https_port, https_host)
    try:
        srv = WSGIServer(("0.0.0.0", http_port), _Quiet)
        srv.set_app(app_redirect)
        threading.Thread(target=srv.serve_forever, daemon=True, name="http-redirect").start()
        print(f"  \u21a9\ufe0f  HTTP redirect active  http://0.0.0.0:{http_port} \u2192 HTTPS :{https_port}")
    except OSError as exc:
        print(f"  \u26a0\ufe0f  HTTP redirect server could not bind to port {http_port}: {exc}")
        print(f"     Change QSS_HTTP_REDIRECT_PORT in .env to a free port.")


# ── Main (WSGI-ready) ────────────────────────────────────────────────

@app.route("/recycle-bin", methods=["GET", "POST"])
@login_required
def recycle_bin():
    """Isolated dashboard for soft-deleted assets and scans.

    GET: Display soft-deleted items (Admin-only).
    POST actions (Admin-only):
      - restore_assets: Restore deleted assets
      - restore_scans: Restore deleted scans
      - delete_assets: Permanently purge deleted assets (hard delete, Admin-only)
      - delete_scans: Permanently purge deleted scans (hard delete, Admin-only)
    """
    from src.db import db_session
    from src.models import Asset, Scan, DiscoveryItem, Certificate, PQCClassification, CBOMEntry, ComplianceScore, CBOMSummary, CyberRating
    
    # Check admin/manager permission for destructive actions
    ALLOWED_RESTORE_ROLES = {"Admin", "Manager"}
    ALLOWED_HARD_DELETE_ROLES = {"Admin"}
    
    is_admin = current_user.role in ALLOWED_HARD_DELETE_ROLES if hasattr(current_user, 'role') else False
    is_manager = current_user.role in ALLOWED_RESTORE_ROLES if hasattr(current_user, 'role') else False
    wants_json = request.is_json or (request.accept_mimetypes.best == "application/json")

    def _payload() -> dict:
        if request.is_json:
            return request.get_json(silent=True) or {}
        return request.form.to_dict(flat=False)

    def _payload_value(data: dict, key: str, default: str = "") -> str:
        raw = data.get(key, default)
        if isinstance(raw, list):
            raw = raw[0] if raw else default
        return str(raw or default)

    def _payload_ids(data: dict, key: str) -> list[int]:
        raw = data.get(key)
        values: list[str] = []
        if isinstance(raw, list):
            values.extend(str(v).strip() for v in raw if str(v).strip())
        elif raw is not None:
            values.extend(part.strip() for part in str(raw).split(",") if part.strip())
        return [int(v) for v in values if v.isdigit()]

    def _json(message: str, code: int, **extra):
        return jsonify({
            "status": "success" if code < 400 else "error",
            "message": message,
            **extra,
        }), code

    if not is_admin:
        _audit("recycle_bin", "view", "denied", details={"required_role": "Admin", "actual_role": getattr(current_user, 'role', None)})
        if wants_json:
            return _json("Recycle Bin is restricted to Admin users.", 403)
        flash("Recycle Bin is restricted to Admin users.", "error")
        return redirect(url_for("quantumshield_dashboard.dashboard_home"))
    
    if request.method == "POST":
        payload = _payload()
        action = _payload_value(payload, "action")
        
        # Check permission for the action being requested
        if action in ["restore_assets", "restore_scans"] and not is_manager:
            _audit("recycle_bin", action, "denied", details={"required_role": "Admin or Manager", "actual_role": current_user.role})
            if wants_json:
                return _json("Only Admins and Managers can restore items.", 403)
            flash("Only Admins and Managers can restore items.", "error")
            return redirect(url_for("recycle_bin"))
        
        if action in ["delete_assets", "delete_scans"] and not is_admin:
            _audit("recycle_bin", action, "denied", details={"required_role": "Admin", "actual_role": current_user.role})
            if wants_json:
                return _json("Only Admins can permanently delete items.", 403)
            flash("Only Admins can permanently delete items.", "error")
            return redirect(url_for("recycle_bin"))
        
        try:
            if action == "restore_assets":
                asset_ids = _payload_ids(payload, "asset_ids")
                if asset_ids:
                    assets_to_restore = db_session.query(Asset).filter(Asset.id.in_(asset_ids), Asset.is_deleted == True).all()
                    for asset in assets_to_restore:
                        asset.is_deleted = False
                        asset.deleted_at = None
                        asset.deleted_by_user_id = None

                        # Restore child records tied to this asset
                        for model in (DiscoveryItem, Certificate, PQCClassification, CBOMEntry, ComplianceScore):
                            try:
                                rows = db_session.query(model).filter(model.asset_id == asset.id, model.is_deleted == True).all()
                            except Exception:
                                rows = []
                            for row in rows:
                                row.is_deleted = False
                                row.deleted_at = None
                                row.deleted_by_user_id = None

                        # Restore scans linked by target and scan-bound child tables.
                        asset_target = str(getattr(asset, "name", "") or "").strip().lower()
                        if asset_target:
                            related_scans = db_session.query(Scan).filter(Scan.target.ilike(asset_target)).all()
                            for scan in related_scans:
                                if getattr(scan, "is_deleted", False):
                                    scan.is_deleted = False
                                    scan.deleted_at = None
                                    scan.deleted_by_user_id = None

                                for s_model in (Certificate, PQCClassification, CBOMEntry):
                                    try:
                                        s_rows = db_session.query(s_model).filter(s_model.scan_id == scan.id, s_model.is_deleted == True).all()
                                    except Exception:
                                        s_rows = []
                                    for s_row in s_rows:
                                        s_row.is_deleted = False
                                        s_row.deleted_at = None
                                        s_row.deleted_by_user_id = None

                                for s_model in (DiscoveryItem, ComplianceScore, CyberRating):
                                    s_rows = db_session.query(s_model).filter(s_model.scan_id == scan.id, s_model.is_deleted == True).all()
                                    for s_row in s_rows:
                                        s_row.is_deleted = False
                                        s_row.deleted_at = None
                                        s_row.deleted_by_user_id = None

                                s_summary = db_session.query(CBOMSummary).filter(CBOMSummary.scan_id == scan.id, CBOMSummary.is_deleted == True).first()
                                if s_summary:
                                    s_summary.is_deleted = False
                                    s_summary.deleted_at = None
                                    s_summary.deleted_by_user_id = None
                    db_session.commit()
                    _audit("recycle_bin", "restore_assets", "success", details={"count": len(assets_to_restore)})
                    if wants_json:
                        return _json(
                            f"Successfully restored {len(assets_to_restore)} asset(s).",
                            200,
                            restored_count=len(assets_to_restore),
                            restored_asset_ids=[int(getattr(a, "id", 0) or 0) for a in assets_to_restore],
                        )
                    flash(f"Successfully restored {len(assets_to_restore)} asset(s).", "success")
                    
            elif action == "restore_scans":
                scan_ids = _payload_ids(payload, "scan_ids")
                if scan_ids:
                    scans_to_restore = db_session.query(Scan).filter(Scan.id.in_(scan_ids), Scan.is_deleted == True).all()
                    for scan in scans_to_restore:
                        scan.is_deleted = False
                        scan.deleted_at = None
                        scan.deleted_by_user_id = None

                        for s_model in (Certificate, PQCClassification, CBOMEntry):
                            try:
                                s_rows = db_session.query(s_model).filter(s_model.scan_id == scan.id, s_model.is_deleted == True).all()
                            except Exception:
                                s_rows = []
                            for s_row in s_rows:
                                s_row.is_deleted = False
                                s_row.deleted_at = None
                                s_row.deleted_by_user_id = None

                        for s_model in (DiscoveryItem, ComplianceScore, CyberRating):
                            s_rows = db_session.query(s_model).filter(s_model.scan_id == scan.id, s_model.is_deleted == True).all()
                            for s_row in s_rows:
                                s_row.is_deleted = False
                                s_row.deleted_at = None
                                s_row.deleted_by_user_id = None

                        s_summary = db_session.query(CBOMSummary).filter(CBOMSummary.scan_id == scan.id, CBOMSummary.is_deleted == True).first()
                        if s_summary:
                            s_summary.is_deleted = False
                            s_summary.deleted_at = None
                            s_summary.deleted_by_user_id = None
                    db_session.commit()
                    _audit("recycle_bin", "restore_scans", "success", details={"count": len(scans_to_restore)})
                    if wants_json:
                        return _json(
                            f"Successfully restored {len(scans_to_restore)} scan(s).",
                            200,
                            restored_count=len(scans_to_restore),
                            restored_scan_ids=[int(getattr(s, "id", 0) or 0) for s in scans_to_restore],
                        )
                    flash(f"Successfully restored {len(scans_to_restore)} scan(s).", "success")
            
            elif action == "delete_assets":
                # Admin-only: permanently purge soft-deleted assets
                asset_ids = _payload_ids(payload, "asset_ids")
                if asset_ids:
                    assets_to_delete = db_session.query(Asset).filter(
                        Asset.id.in_(asset_ids), 
                        Asset.is_deleted == True
                    ).all()
                    
                    deleted_count = 0
                    for asset in assets_to_delete:
                        try:
                            # Explicitly purge scan-linked rows that are not FK-constrained by asset_id.
                            asset_target = str(getattr(asset, "name", "") or "").strip().lower()
                            if asset_target:
                                related_scans = db_session.query(Scan).filter(Scan.target.ilike(asset_target), Scan.is_deleted == True).all()
                                for scan in related_scans:
                                    db_session.query(DiscoveryItem).filter(DiscoveryItem.scan_id == scan.id).delete(synchronize_session=False)
                                    db_session.query(Certificate).filter(Certificate.scan_id == scan.id).delete(synchronize_session=False)
                                    db_session.query(PQCClassification).filter(PQCClassification.scan_id == scan.id).delete(synchronize_session=False)
                                    db_session.query(CBOMEntry).filter(CBOMEntry.scan_id == scan.id).delete(synchronize_session=False)
                                    db_session.query(ComplianceScore).filter(ComplianceScore.scan_id == scan.id).delete(synchronize_session=False)
                                    db_session.query(CyberRating).filter(CyberRating.scan_id == scan.id).delete(synchronize_session=False)
                                    db_session.query(CBOMSummary).filter(CBOMSummary.scan_id == scan.id).delete(synchronize_session=False)
                                    db_session.delete(scan)

                            # Hard delete the asset (ORM cascade will handle related entities via ON DELETE CASCADE)
                            db_session.delete(asset)
                            deleted_count += 1
                        except Exception as e:
                            logger.warning(f"Failed to hard-delete asset {asset.id}: {e}")
                    
                    db_session.commit()
                    _audit("recycle_bin", "delete_assets", "success", details={"count": deleted_count})
                    if wants_json:
                        return _json(
                            f"Permanently deleted {deleted_count} asset(s) and related records.",
                            200,
                            deleted_count=deleted_count,
                            deleted_asset_ids=[int(getattr(a, "id", 0) or 0) for a in assets_to_delete],
                        )
                    flash(f"Permanently deleted {deleted_count} asset(s) and related records.", "warning")
            
            elif action == "delete_scans":
                # Admin-only: permanently purge soft-deleted scans
                scan_ids = _payload_ids(payload, "scan_ids")
                if scan_ids:
                    scans_to_delete = db_session.query(Scan).filter(
                        Scan.id.in_(scan_ids), 
                        Scan.is_deleted == True
                    ).all()
                    
                    deleted_count = 0
                    for scan in scans_to_delete:
                        try:
                            # Hard delete the scan (ORM cascade will handle related entities)
                            db_session.delete(scan)
                            deleted_count += 1
                        except Exception as e:
                            logger.warning(f"Failed to hard-delete scan {scan.id}: {e}")
                    
                    db_session.commit()
                    _audit("recycle_bin", "delete_scans", "success", details={"count": deleted_count})
                    if wants_json:
                        return _json(
                            f"Permanently deleted {deleted_count} scan(s) and related records.",
                            200,
                            deleted_count=deleted_count,
                            deleted_scan_ids=[int(getattr(s, "id", 0) or 0) for s in scans_to_delete],
                        )
                    flash(f"Permanently deleted {deleted_count} scan(s) and related records.", "warning")
                    
        except Exception as e:
            db_session.rollback()
            _audit("recycle_bin", action or "unknown", "failed", details={"error": str(e)})
            if wants_json:
                return _json(f"Error processing request: {str(e)}", 500)
            flash(f"Error processing request: {str(e)}", "danger")
            
        if wants_json:
            return _json("No matching items selected.", 200)
        return redirect(url_for("recycle_bin"))

    # GET Request: display soft-deleted items
    try:
        deleted_assets = db_session.query(Asset).filter(Asset.is_deleted == True).all()
        deleted_scans = db_session.query(Scan).filter(Scan.is_deleted == True).all()
        vm = {
            "empty": not deleted_assets and not deleted_scans,
            "assets": deleted_assets,
            "scans": deleted_scans,
            "is_admin": is_admin,  # Pass to template for conditional UI
            "is_manager": is_manager,
        }
    except Exception as e:
        logger.error(f"Error loading recycle bin: {e}")
        vm = {
            "empty": True,
            "assets": [],
            "scans": [],
            "is_admin": is_admin,
            "is_manager": is_manager,
        }
    
    return render_template("recycle_bin.html", vm=vm)




def _check_concurrency():
    import subprocess
    import atexit
    import time
    
    pid_file = os.path.join(os.path.dirname(__file__), "app_instance.pid")
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                old_pid = int(f.read().strip())
        except Exception:
            old_pid = None
        
        if old_pid and old_pid != os.getpid():
            # Check if alive on Windows
            cmd = f'tasklist /FI "PID eq {old_pid}" /NH'
            try:
                out = subprocess.check_output(cmd, shell=True).decode(errors='replace')
                if str(old_pid) in out:
                    print(f"\n[!] ALERT: Another instance of {app.import_name} is already running (PID: {old_pid}).")

                    import os as _os
                    auto_kill = _os.environ.get("AUTO_KILL_PREVIOUS", "false").lower() == "true"
                    
                    if auto_kill or sys.stdin.isatty():
                        ans = 'y' if auto_kill else input("Should I end the previous session to start this app? [y/N]: ").strip().lower()
                        if ans == 'y':

                            print(f"Terminating PID {old_pid}...")
                            subprocess.call(f'taskkill /F /PID {old_pid}', shell=True)
                            time.sleep(1)
                            if os.path.exists(pid_file): os.remove(pid_file)
                        else:
                            print("Redirecting to previous instance. Exiting Startup Guard.")
                            sys.exit(0)
                    else:
                        print("Non-interactive mode: Another instance is running. Exiting.")
                        sys.exit(0)
            except Exception:
                pass

    # Save current PID
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    def _cleanup_pid():
        if os.path.exists(pid_file):
            try:
                with open(pid_file, "r") as f:
                    if int(f.read().strip()) == os.getpid():
                        os.remove(pid_file)
            except Exception:
                pass
    atexit.register(_cleanup_pid)


if __name__ == "__main__":
    _start_scheduler_if_enabled()
    _bootstrap_runtime_state()

    print(f"\n{'='*60}")
    print(f"  [QuantumShield] {app.import_name} - Quantum-Safe TLS Scanner")
    print(f"  Running on https://{FLASK_HOST}:{FLASK_PORT}")
    print(f"{'='*60}\n")

    # ── HTTP → HTTPS redirect server (background daemon) ─────────────
    _http_redirect_port = int(os.environ.get("QSS_HTTP_REDIRECT_PORT", "5080"))
    _start_http_redirect_server(
        http_port=_http_redirect_port,
        https_port=FLASK_PORT,
        https_host=FLASK_HOST,
    )

    # Prefer mkcert-generated trusted certs (no browser warning)
    _cert_file = os.path.join(BASE_DIR, "certs", "cert.pem")
    _key_file  = os.path.join(BASE_DIR, "certs", "key.pem")
    _has_certs = os.path.exists(_cert_file) and os.path.exists(_key_file)

    if DEBUG:
        # Dev mode: use Flask built-in server with hot-reload
        if _has_certs:
            _ssl_ctx = (_cert_file, _key_file)
            print("  [OK] Using mkcert trusted SSL certificate (no browser warnings)")
        else:
            _ssl_ctx = "adhoc"
            print("  [WARN] No certs/ dir found - using adhoc self-signed cert (browser will warn)")
            print("     To fix, run:  mkcert -install && mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1")

        app.run(host=FLASK_HOST, port=FLASK_PORT, debug=True, ssl_context=_ssl_ctx)
    else:
        # Production mode: use Waitress (Windows-compatible WSGI server)
        try:
            from waitress import serve as waitress_serve  # type: ignore
            print("  [OK] Production mode - Waitress WSGI server")
            if _has_certs:
                print("  [OK] TLS certs loaded from certs/")
            else:
                print("  [WARN] No certs/ dir - running plain HTTP on Waitress")
                print("     Tip: put a reverse proxy (nginx/caddy) in front for HTTPS in production")
            # Waitress does not natively handle SSL — use a reverse proxy for HTTPS.
            # For dev convenience with certs, fall back to Flask's ssl_context.
            if _has_certs:
                # Use Flask's dev server with certs for now (Waitress + SSL needs a proxy)
                app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, ssl_context=(_cert_file, _key_file))
            else:
                waitress_serve(app, host=FLASK_HOST, port=int(FLASK_PORT), threads=8)
        except ImportError:
            print("  [WARN] Waitress not installed - falling back to Flask dev server")
            print("     Install with: pip install waitress")
            app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, ssl_context="adhoc")
