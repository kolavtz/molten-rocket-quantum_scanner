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
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

import json

import os
import uuid
import traceback
import logging
import socket
import urllib.request
import urllib.parse
from datetime import datetime, timezone

from flask import (
    Flask,
    g,
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
from functools import wraps

import sys
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
from src import database as db

# ── Flask App ────────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)
app.secret_key = SECRET_KEY

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
)

if TRUST_PROXY_SSL_HEADER:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

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
)

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


SCAN_ROLES = {"Admin", "Manager", "SingleScan"}
BULK_SCAN_ROLES = {"Admin", "Manager"}
ADMIN_PANEL_ROLES = {"Admin"}
ALL_APP_ROLES = {"Admin", "Manager", "SingleScan", "Viewer"}

# ── Theme Configuration ───────────────────────────────────────────
THEME_FILE = os.path.join(os.path.dirname(__file__), "theme.json")

def load_theme():
    default_theme = {
        "bg_navbar": "rgba(15, 18, 25, 0.92)",
        "accent_color": "#4a9ead",
        "bg_primary": "#0f1219",
        "text_primary": "#f3f4f6"
    }
    if os.path.exists(THEME_FILE):
        try:
            with open(THEME_FILE, 'r') as f:
                data = json.load(f)
                return {**default_theme, **data}
        except Exception:
            pass
    return default_theme

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


def _normalize_tls_result(raw_result: dict) -> dict:
    """Normalize TLS analyzer output into dashboard/report-friendly schema."""
    raw = dict(raw_result or {})
    cert = raw.get("certificate") if isinstance(raw.get("certificate"), dict) else {}
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
        "serial_number": str(cert.get("serial_number") or ""),
        "key_type": str(cert.get("public_key_type") or "Unknown"),
        "key_size": key_bits,
        "key_length": key_bits,
        "signature_algorithm": str(cert.get("signature_algorithm") or ""),
        "cert_sha256": str(cert.get("fingerprint_sha256") or ""),
        "san_domains": cert.get("san_domains") if isinstance(cert.get("san_domains"), list) else [],
        "valid_from": _parse_cert_time(str(cert.get("not_before") or "")),
        "valid_to": _parse_cert_time(str(cert.get("not_after") or "")),
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

# Initialise MySQL (if available) and hydrate scan_store
logger.info("Initializing database connectivity...")
_db_available = db.init_db()
logger.info("Database initialization complete. Available=%s", _db_available)
if _db_available:
    for _report in db.list_scans(limit=100):
        _sid = _report.get("scan_id")
        if _sid:
            scan_store[_sid] = _report
    print(f"  💾 MySQL connected — loaded {len(scan_store)} scans from database")
else:
    # Fallback: load from JSON files on disk
    for _fname in os.listdir(RESULTS_DIR):
        if _fname.endswith("_report.json"):
            try:
                with open(os.path.join(RESULTS_DIR, _fname), "r", encoding="utf-8") as _fh:
                    _report = json.load(_fh)
                    _sid = _report.get("scan_id")
                    if _sid:
                        scan_store[_sid] = _report
            except Exception:
                pass
    print(f"  📂 JSON-only mode — loaded {len(scan_store)} scans from disk")

# ── Pipeline ─────────────────────────────────────────────────────────


def run_scan_pipeline(target: str, ports: list[int] | None = None, asset_class_hint: str | None = None) -> dict:
    """Execute the full scan pipeline and return a report dict."""
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
    from src.models import Scan, Asset, Certificate, DiscoveryItem, PQCClassification, CBOMSummary, CBOMEntry, ComplianceScore
    from sqlalchemy.exc import SQLAlchemyError
    try:
        dt = datetime.strptime(report.get("timestamp", datetime.now(timezone.utc).isoformat()), "%Y-%m-%dT%H:%M:%S.%f%z") if "." in report.get("timestamp", "") else datetime.now()
        overall_score = sum(float(pq.get("score", 0)) for pq in pqc_dicts) / max(len(pqc_dicts), 1)
        
        db_scan = Scan(
            target=target,
            status="complete",
            started_at=dt,
            completed_at=datetime.now(),
            total_assets=len(discovered_services),
            overall_pqc_score=overall_score,
            cbom_path=cbom_path
        )
        db_session.add(db_scan)
        db_session.flush()

        scan_pk = getattr(db_scan, "id", None) or getattr(db_scan, "scan_id", None)
        
        # Resolve Asset
        inventory_asset = db_session.query(Asset).filter_by(name=target, is_deleted=False).first()
        asset_id = inventory_asset.id if inventory_asset else None
        
        # Discovery Items
        for svc in discovered_services:
            discovery_item = DiscoveryItem(
                asset_id=asset_id,
                type="ip",
                status="new",
                detection_date=datetime.now()
            )
            if hasattr(db_scan, "discovery_items"):
                db_scan.discovery_items.append(discovery_item)
            elif hasattr(discovery_item, "scan_id") and scan_pk is not None:
                discovery_item.scan_id = scan_pk
                db_session.add(discovery_item)
            
        # TLS & Certificates
        for tls in tls_results:
            cert_obj = Certificate(
                asset_id=asset_id,
                issuer=str(tls.get("issuer", {}).get("O", "Unknown")),
                subject=str(tls.get("subject", {}).get("O", "Unknown")),
                serial=tls.get("serial_number", ""),
                valid_from=tls.get("valid_from_dt"),
                valid_until=tls.get("valid_until_dt"),
                tls_version=tls.get("protocol_version", ""),
                key_length=int(tls.get("key_length", 0) or tls.get("key_size", 0)),
                cipher_suite=tls.get("cipher_suite", ""),
                ca=str(tls.get("issuer", {}).get("CN", "Unknown"))
            )
            if hasattr(db_scan, "certificates"):
                db_scan.certificates.append(cert_obj)
            elif hasattr(cert_obj, "scan_id") and scan_pk is not None:
                cert_obj.scan_id = scan_pk
                db_session.add(cert_obj)
            
        # PQC
        for pq in pqc_dicts:
            pqc_obj = PQCClassification(
                asset_id=asset_id,
                algorithm_name=pq.get("algorithm", "Unknown"),
                algorithm_type=pq.get("category", "Unknown"),
                quantum_safe_status=pq.get("status", "Unknown"),
                nist_category=pq.get("nist_status", "None"),
                pqc_score=float(pq.get("score", 0))
            )
            if hasattr(db_scan, "pqc_classifications"):
                db_scan.pqc_classifications.append(pqc_obj)
            elif hasattr(pqc_obj, "scan_id") and scan_pk is not None:
                pqc_obj.scan_id = scan_pk
                db_session.add(pqc_obj)
            
        # CBOM
        cbom_summary = CBOMSummary(
            total_components=len(pqc_dicts) + len(tls_results),
            weak_crypto_count=sum(1 for tls in tls_results if tls.get("protocol_version") in ("TLS 1.0", "SSLv3")),
            cert_issues_count=0,
            json_path=cbom_path
        )
        if hasattr(db_scan, "cbom_summary"):
            db_scan.cbom_summary = cbom_summary
        elif hasattr(cbom_summary, "scan_id") and scan_pk is not None:
            cbom_summary.scan_id = scan_pk
            db_session.add(cbom_summary)
        
        for cmp in cbom_dict.get("components", []):
            cbom_entry = CBOMEntry(
                asset_id=asset_id,
                algorithm_name=cmp.get("name", ""),
                category=cmp.get("type", "crypto-asset"),
                nist_status="Unknown",
                quantum_safe_flag=False,
                hndl_level="Medium"
            )
            if hasattr(db_scan, "cbom_entries"):
                db_scan.cbom_entries.append(cbom_entry)
            elif hasattr(cbom_entry, "scan_id") and scan_pk is not None:
                cbom_entry.scan_id = scan_pk
                db_session.add(cbom_entry)

        db_session.commit()
    except SQLAlchemyError as err:
        db_session.rollback()
        import traceback
        print(f"Failed to ingest native DB schema: {err}")
        traceback.print_exc()
        
    # Store in memory primarily for caching/legacy access if needed
    scan_store[scan_id] = report
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
        new_theme = {
            "bg_navbar": request.form.get("bg_navbar", current_theme["bg_navbar"]),
            "accent_color": request.form.get("accent_color", current_theme["accent_color"]),
            "bg_primary": request.form.get("bg_primary", current_theme["bg_primary"]),
            "text_primary": request.form.get("text_primary", current_theme["text_primary"])
        }
        try:
            with open(THEME_FILE, 'w') as f:
                json.dump(new_theme, f, indent=4)
            _audit("admin", "update_theme", "success")
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
    """Admin-triggered password reset email for an existing user."""
    user = db.get_user_by_id(user_id)
    if not user:
        _audit("admin", "reset_password", "failed", target_user_id=user_id, details={"reason": "user_not_found"})
        flash("User not found or inactive.", "error")
        return redirect(url_for("admin_users"))
    if not user.get("email"):
        _audit("admin", "reset_password", "failed", target_user_id=user_id, details={"reason": "missing_email"})
        flash("User has no email configured.", "error")
        return redirect(url_for("admin_users"))

    token = db.create_password_setup_token(user_id, expires_hours=24)
    if not token:
        _audit("admin", "reset_password", "failed", target_user_id=user_id, details={"reason": "token_generation_failed"})
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
        flash("Password reset email sent.", "success")
    except Exception as exc:
        logger.error("Password reset email failed for %s: %s", user["email"], exc)
        _audit("admin", "reset_password", "partial", target_user_id=user_id, details={"email": user["email"], "email_sent": False, "error": str(exc)})
        flash(f"SMTP failed. Temporary setup link: {setup_url}", "warning")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<user_id>/update", methods=["POST"])
@role_required(list(ADMIN_PANEL_ROLES))
def admin_update_user(user_id: str):
    role = db.normalize_role(request.form.get("role") or "Viewer")
    is_active = request.form.get("is_active") == "on"
    if db.update_user_profile(user_id, role=role, is_active=is_active):
        _audit("admin", "update_user", "success", target_user_id=user_id, details={"role": role, "is_active": is_active})
        flash("User profile updated.", "success")
    else:
        _audit("admin", "update_user", "failed", target_user_id=user_id, details={"role": role, "is_active": is_active})
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

    # Use the Direct MySQL Aggegate Loader for dashboard performance instead of loops
    enterprise_metrics = db.get_enterprise_metrics()
    
    # Ensure zero-state consistency using AssetService aggregates if DB totals fail
    if not enterprise_metrics or enterprise_metrics.get("total_assets", 0) == 0:
        logger.info("Direct enterprise metrics empty. Utilizing AssetService aggregations.")
        from src.services.asset_service import AssetService
        asset_svc = AssetService()
        assets = asset_svc.load_combined_assets()
        summary = asset_svc.get_dashboard_summary(assets)
        
        enterprise_metrics = {
            "total_assets": summary.get("total_assets", 0),
            "quantum_safe": max(0, summary.get("total_assets", 0) - summary.get("expiring_certs", 0)), 
            "quantum_vulnerable": 0,
            "total_score": 0,
            "scan_count": len(recent_scans),
            "avg_score": summary.get("overall_risk_score", 0),
            "critical_findings": summary.get("risk_distribution", {}).get("Critical", 0),
            "api_services": summary.get("api_count", 0),
            "asset_class_distribution": {
                "APIs": summary.get("api_count", 0),
                "VPNs": summary.get("vpn_count", 0),
                "Servers": summary.get("server_count", 0),
                "Web Apps": max(0, summary.get("total_assets", 0) - summary.get("api_count", 0) - summary.get("vpn_count", 0) - summary.get("server_count", 0))
            },
            "risk_distribution": summary.get("risk_distribution", {}),
            "ssl_expiry": {"0-30": summary.get("expiring_certs", 0)},
            "ssl_expiry_extended": {},
            "ip_breakdown": {},
            "crypto_overview": [],
            "certificate_inventory": [],
            "dns_records_total": 0,
            "latest_scan": recent_scans[0].get("scanned_at") if recent_scans else "Never"
        }

    # Verify inventory_vm aggregation
    inventory_vm = _build_asset_inventory_view()

    return render_template(
        "home1.html",
        recent_scans=recent_scans,
        enterprise_metrics=enterprise_metrics,
        inventory_vm=inventory_vm,
    )

# Register Main Dashboard Blueprint
from web.blueprints.dashboard import dashboard_bp
app.register_blueprint(dashboard_bp)

# Inventory status polling runs frequently from UI; keep it outside tight default limits.
if "quantumshield_dashboard.inventory_scan_status" in app.view_functions:
    limiter.limit("2000 per hour")(app.view_functions["quantumshield_dashboard.inventory_scan_status"])




@app.route("/scan-center")
@role_required(list(SCAN_ROLES))
def scan_center():
    """Dedicated page for scan initiation workflows."""
    return render_template("scan_center.html")


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
    """Build inventory view-model from both database assets AND live scans."""
    from collections import Counter
    import ipaddress
    from src.db import db_session
    from src.models import Asset

    assets: list[dict] = []
    nameserver_records: list[dict] = []
    crypto_overview: list[dict] = []
    asset_locations: list[dict] = []
    certificate_inventory: list[dict] = []
    cert_bucket = Counter({"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0})
    visited_targets = set()

    # First, load all assets from the Asset table (database)
    db_assets = db_session.query(Asset).filter(Asset.is_deleted == False).all()
    
    for db_asset in db_assets:
        updated_at = getattr(db_asset, "updated_at", None)
        asset_name = str(getattr(db_asset, "name", "") or "")
        asset_dict = {
            "asset_name": asset_name,
            "url": str(getattr(db_asset, "url", "") or f"https://{asset_name}"),
            "ipv4": str(getattr(db_asset, "ipv4", "") or ""),
            "ipv6": str(getattr(db_asset, "ipv6", "") or ""),
            "type": str(getattr(db_asset, "asset_type", "") or "Web App"),
            "asset_class": "Database",
            "owner": str(getattr(db_asset, "owner", "") or "Unassigned"),
            "risk": str(getattr(db_asset, "risk_level", "") or "Medium"),
            "cert_status": "Not Scanned",
            "key_length": 0,
            "last_scan": _iso_date(str(updated_at)) if updated_at else "Pending",
        }
        assets.append(asset_dict)
        visited_targets.add(asset_name)

    # Then augment with scan data for scanned assets
    scans_feed = []
    seen_scan_ids = set()
    for scan in scan_store.values():
        if isinstance(scan, dict):
            sid = str(scan.get("scan_id") or "")
            seen_scan_ids.add(sid)
            scans_feed.append(scan)
    for scan in db.list_scans(limit=100):
        if not isinstance(scan, dict):
            continue
        sid = str(scan.get("scan_id") or "")
        if sid and sid in seen_scan_ids:
            continue
        scans_feed.append(scan)

    for scan in scans_feed:
        if scan.get("status") != "complete":
            continue

        target = str(scan.get("target", "")).strip()
        host = _host_from_target(target)
        if not host:
            continue

        overview = scan.get("overview") or {}
        tls_results = scan.get("tls_results") or []
        discovered = scan.get("discovered_services") or []
        score = float(overview.get("average_compliance_score") or 0)
        risk = _score_to_risk(score if score > 100 else score * 10)

        ipv4 = ""
        ipv6 = ""
        for svc in discovered:
            cand = str(svc.get("host", ""))
            if not cand:
                continue
            try:
                parsed = ipaddress.ip_address(cand)
                if parsed.version == 4 and not ipv4:
                    ipv4 = cand
                if parsed.version == 6 and not ipv6:
                    ipv6 = cand
            except ValueError:
                continue

        first = tls_results[0] if tls_results else {}
        key_length = first.get("key_size") or first.get("key_length") or 0
        tls_version = first.get("tls_version") or "Unknown"
        ciphers = first.get("cipher_suites") or []
        cipher_suite = ciphers[0] if ciphers else "Unknown"
        issuer = first.get("issuer") if isinstance(first.get("issuer"), dict) else {}
        issuer_name = issuer.get("O") or issuer.get("CN") or "Unknown"

        cert_days = first.get("cert_days_remaining")
        cert_status = "Unknown"
        if isinstance(cert_days, (int, float)):
            if cert_days < 0:
                cert_status = "Expired"
            elif cert_days <= 30:
                cert_status = "Expiring"
                cert_bucket["0-30"] += 1
            elif cert_days <= 60:
                cert_status = "Valid"
                cert_bucket["30-60"] += 1
            elif cert_days <= 90:
                cert_status = "Valid"
                cert_bucket["60-90"] += 1
            else:
                cert_status = "Valid"
                cert_bucket[">90"] += 1
 
        if tls_results:
            first_tr = tls_results[0]
            certificate_inventory.append({
                "asset": host,
                "issuer": issuer_name,
                "key_length": key_length,
                "tls_version": tls_version,
                "days_remaining": cert_days if isinstance(cert_days, (int, float)) else None,
                "status": cert_status,
            })

        kind = "Web App"
        if any("api" in str(s).lower() for s in (host, target)):
            kind = "API"
        elif any("gateway" in str(s).lower() for s in (host, target)):
            kind = "Load Balancer"
        elif discovered:
            kind = "Server"

        # Update existing asset with scan data if it exists
        existing_asset = next((a for a in assets if a["asset_name"].lower() == host.lower()), None)
        if existing_asset:
            existing_asset.update({
                "ipv4": ipv4 or existing_asset.get("ipv4"),
                "ipv6": ipv6 or existing_asset.get("ipv6"),
                "type": kind,
                "risk": risk,
                "cert_status": cert_status,
                "key_length": key_length,
                "last_scan": _iso_date(str(scan.get("generated_at", ""))),
                "asset_class": "Scanned",
            })
        else:
            # New asset from scan not in database yet
            row = {
                "asset_name": host,
                "url": target if str(target).startswith("http") else f"https://{host}",
                "ipv4": ipv4,
                "ipv6": ipv6,
                "type": kind,
                "asset_class": "Scanned",
                "owner": "Infra",
                "risk": risk,
                "cert_status": cert_status,
                "key_length": key_length,
                "last_scan": _iso_date(str(scan.get("generated_at", ""))),
            }
            assets.append(row)

        crypto_overview.append({
            "asset": host,
            "key_length": key_length,
            "cipher_suite": cipher_suite,
            "tls_version": tls_version,
            "ca": issuer_name,
            "last_scan": _iso_date(str(scan.get("generated_at", ""))),
        })

        for dns_row in (scan.get("dns_records") or []):
            if not isinstance(dns_row, dict):
                continue
            nameserver_records.append(
                {
                    "hostname": str(dns_row.get("hostname") or host),
                    "type": str(dns_row.get("record_type") or "A"),
                    "ip": str(dns_row.get("record_value") or "") if str(dns_row.get("record_type") or "").upper() in {"A", "MX", "NS", "PTR", "CNAME"} else "",
                    "ipv6": str(dns_row.get("record_value") or "") if str(dns_row.get("record_type") or "").upper() == "AAAA" else "",
                    "ttl": int(dns_row.get("ttl") or 300),
                }
            )

        for loc in (scan.get("asset_locations") or []):
            if not isinstance(loc, dict):
                continue
            lat = loc.get("lat")
            lon = loc.get("lon")
            if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
                continue
            asset_locations.append(
                {
                    "asset": host,
                    "ip": str(loc.get("ip") or ""),
                    "lat": float(lat),
                    "lon": float(lon),
                    "city": str(loc.get("city") or ""),
                    "region": str(loc.get("region") or ""),
                    "country": str(loc.get("country") or ""),
                }
            )

    # Calculate KPIs from the complete asset list
    kpis = {
        "total_assets": len(assets),
        "public_web_apps": sum(1 for a in assets if a["type"] == "Web App"),
        "apis": sum(1 for a in assets if a["type"] == "API"),
        "servers": sum(1 for a in assets if a["type"] == "Server"),
        "expiring_certificates": sum(1 for a in assets if a["cert_status"] == "Expiring"),
        "high_risk_assets": sum(1 for a in assets if a["risk"] in {"Critical", "High"}),
    }

    type_dist = Counter(a["type"] for a in assets)
    risk_dist = Counter(a["risk"] for a in assets)
    ipv4_count = sum(1 for a in assets if a["ipv4"])
    ipv6_count = sum(1 for a in assets if a["ipv6"])
    total_ip_assets = max(1, ipv4_count + ipv6_count)

    owners = sorted({a["owner"] for a in assets}) or ["Infra"]
    heatmap = []
    for owner in owners:
        owner_rows = [a for a in assets if a["owner"] == owner]
        for band in ("Critical", "High", "Medium", "Low"):
            value = sum(1 for a in owner_rows if a["risk"] == band)
            heatmap.append({"x": owner, "y": band, "value": value})

    return {
        "empty": len(assets) == 0,
        "kpis": kpis,
        "asset_type_distribution": {
            "Web Applications": type_dist.get("Web App", 0),
            "APIs": type_dist.get("API", 0),
            "Servers": type_dist.get("Server", 0),
            "Load Balancers": type_dist.get("Load Balancer", 0),
            "Other": type_dist.get("Other", 0),
        },
        "asset_risk_distribution": {
            "Critical": risk_dist.get("Critical", 0),
            "High": risk_dist.get("High", 0),
            "Medium": risk_dist.get("Medium", 0),
            "Low": risk_dist.get("Low", 0),
        },
        "risk_heatmap": heatmap,
        "certificate_expiry_timeline": dict(cert_bucket),
        "ip_version_breakdown": {
            "IPv4": round((ipv4_count * 100) / total_ip_assets),
            "IPv6": round((ipv6_count * 100) / total_ip_assets),
        },
        "assets": assets,
        "nameserver_records": nameserver_records,
        "crypto_overview": crypto_overview,
        "asset_locations": asset_locations,
        "certificate_inventory": certificate_inventory,
    }


def _build_asset_discovery_view(include_in_progress: bool = False) -> dict:
    """Build discovery view from live scan artifacts only."""
    from collections import Counter
    import ipaddress

    domains: list[dict] = []
    ssl: list[dict] = []
    ip_subnets: list[dict] = []
    software: list[dict] = []
    nodes: list[dict] = []
    edges: list[dict] = []

    node_ids: set[str] = set()
    edge_ids: set[str] = set()

    # Pre-load known assets for cross-correlation
    known_assets = {
        str(a.get("target") or a.get("name") or a.get("asset_name") or "").strip()
        for a in db.list_assets()
        if str(a.get("target") or a.get("name") or a.get("asset_name") or "").strip()
    }

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
    seen_scan_ids = set()
    for scan in scan_store.values():
        if isinstance(scan, dict):
            sid = str(scan.get("scan_id") or "")
            seen_scan_ids.add(sid)
            scans_feed.append(scan)
    for scan in db.list_scans(limit=100):
        if not isinstance(scan, dict):
            continue
        sid = str(scan.get("scan_id") or "")
        if sid and sid in seen_scan_ids:
            continue
        scans_feed.append(scan)

    for scan in scans_feed:
        if scan.get("status") != "complete" and not include_in_progress:
            continue

        target = str(scan.get("target", "")).strip()
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
                            "location": "",
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

    status_counts = Counter(
        [r.get("status", "") for r in domains + ssl + ip_subnets + software if r.get("status")]
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
        "graph_payload": {
            "nodes": nodes,
            "edges": edges,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


@app.route("/asset-inventory")
@login_required
def asset_inventory_page():
    from src.db import db_session
    from src.models import Asset
    items = (
        db_session.query(Asset)
        .filter(Asset.is_deleted == False)
        .order_by(Asset.name.asc())
        .all()
    )
    page_data = {
        "items": items,
        "total_count": len(items),
        "page": 1,
        "page_size": len(items),
        "total_pages": 1,
        "has_next": False,
        "has_prev": False,
    }

    try:
        vm = _build_asset_inventory_view()
    except Exception as e:
        import traceback
        print(f"\n[!] Error building asset inventory view: {e}")
        traceback.print_exc()
        vm = {"empty": True, "kpis": {}, "asset_type_distribution": {}, "risk_heatmap": [], "ip_version_breakdown": {}}

        
    return render_template("asset_inventory.html", page_data=page_data, vm=vm)


@app.route("/asset-discovery")
@login_required
def asset_discovery():
    from flask import request
    from src.db import db_session
    from src.models import Scan
    from src.table_helper import paginate_query
    
    # We will use 'tab' parameter to define which model to paginate in future revisions
    # For now, we will pass an empty page_data to avoid crashing the macro injection UI until Discovery DB tables operate
    page_data = {"items": [], "total_count": 0, "has_next": False, "has_prev": False}

    try:
        vm = _build_asset_discovery_view()
    except Exception:
        vm = {"empty": True, "graph_payload": {"nodes": [], "edges": []}, "status_counts": {}}
        
    return render_template("asset_discovery.html", vm=vm, page_data=page_data)


@app.route("/api/discovery-graph")
@csrf.exempt
@login_required
def discovery_graph_payload():
    """Realtime discovery graph payload for incremental frontend updates."""
    _audit("scan", "discovery_graph_requested", "success")
    try:
        vm = _build_asset_discovery_view(include_in_progress=True)
        return jsonify({"status": "success", "data": vm.get("graph_payload", {"nodes": [], "edges": [], "updated_at": ""})}, ), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


def _inventory_scan_service_for_api():
    """Create inventory scan service bound to the app's scan pipeline."""
    from src.services.inventory_scan_service import InventoryScanService

    scan_runner = app.config.get("RUN_SCAN_PIPELINE_FUNC")
    return InventoryScanService(scan_runner=scan_runner)


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
        return jsonify(result), code
    except Exception as exc:
        _audit("scan", "inventory_scan_all", "failed", details={"error": str(exc)})
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/inventory/scan-status", methods=["GET"])
@role_required(list(SCAN_ROLES))
def api_inventory_scan_status():
    """Return inventory scan progress/status payload."""
    try:
        scan_service = _inventory_scan_service_for_api()
        status_data = scan_service.get_scan_status()
        _audit("scan", "inventory_scan_status_requested", "success", details={"status": status_data.get("status")})
        return jsonify({"status": "success", "data": status_data}), 200
    except Exception as exc:
        _audit("scan", "inventory_scan_status_requested", "failed", details={"error": str(exc)})
        return jsonify({"status": "error", "message": str(exc)}), 500


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
            return jsonify({"status": "error", "message": "Asset not found"}), 404

        scan_service = _inventory_scan_service_for_api()
        result = scan_service.scan_asset(asset)
        db_session.commit()
        code = 200 if result.get("status") == "complete" else 202
        _audit("scan", "inventory_scan_asset", "success", details={"asset_id": asset_id, "status": result.get("status")})
        return jsonify({"status": result.get("status"), "data": result}), code
    except Exception as exc:
        db_session.rollback()
        _audit("scan", "inventory_scan_asset", "failed", details={"asset_id": asset_id, "error": str(exc)})
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/inventory/asset/<int:asset_id>/history", methods=["GET"])
@role_required(list(SCAN_ROLES))
def api_inventory_asset_history(asset_id: int):
    """Return scan history for a single inventory asset."""
    try:
        scan_service = _inventory_scan_service_for_api()
        history = scan_service.get_asset_scan_history(asset_id)
        _audit("scan", "inventory_asset_history_requested", "success", details={"asset_id": asset_id})
        return jsonify({"status": "success", "data": history}), 200
    except Exception as exc:
        _audit("scan", "inventory_asset_history_requested", "failed", details={"asset_id": asset_id, "error": str(exc)})
        return jsonify({"status": "error", "message": str(exc)}), 500


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
            interval_hours = int(interval_raw)

            if interval_hours < 1 or interval_hours > 168:
                return jsonify({"status": "error", "message": "Interval must be between 1 and 168 hours"}), 400

            os.environ["INVENTORY_SCAN_ENABLED"] = str(enabled)
            os.environ["INVENTORY_SCAN_INTERVAL_HOURS"] = str(interval_hours)
            return jsonify({
                "status": "success",
                "message": "Schedule updated",
                "settings": {"enabled": enabled, "interval_hours": interval_hours},
            })

        from config import AUTOMATED_SCAN_ENABLED, AUTOMATED_SCAN_INTERVAL_HOURS
        return jsonify({
            "status": "success",
            "data": {"enabled": AUTOMATED_SCAN_ENABLED, "interval_hours": AUTOMATED_SCAN_INTERVAL_HOURS},
        })
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/cbom-dashboard")
@login_required
def cbom_dashboard():
    """Build CBOM view with real cryptographic metrics."""
    from src.db import db_session
    from src.models import Certificate, Scan
    from sqlalchemy import func
    from collections import Counter
    try:
        cert_count = db_session.query(func.count(Certificate.id)).scalar() or 0
        weak_tls = db_session.query(func.count(Certificate.id)).filter(Certificate.tls_version.in_(["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"])).scalar() or 0
        weak_keys = db_session.query(func.count(Certificate.id)).filter(Certificate.key_length < 2048).scalar() or 0
        
        # Real scan count (unique targets scanned)
        scan_count = db_session.query(func.count(func.distinct(Scan.target))).filter(Scan.status == "complete").scalar() or 0
        
        items = db_session.query(Certificate).order_by(Certificate.id.desc()).all()
        page_data = {
            "items": items,
            "total_count": len(items),
            "page": 1,
            "page_size": len(items),
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        }

        # Calculate key length distribution
        certs = db_session.query(Certificate).all()
        key_dist = Counter()
        cipher_dist = Counter()
        ca_dist = Counter()
        tls_dist = Counter()
        
        for cert in certs:
            key_length_value = getattr(cert, "key_length", None)
            kl = int(key_length_value) if key_length_value is not None else 0
            if kl >= 4096:
                key_dist["4096+"] += 1
            elif kl >= 2048:
                key_dist["2048-4095"] += 1
            elif kl > 0:
                key_dist[f"<2048"] += 1
            
            cipher_suite = str(getattr(cert, "cipher_suite", "") or "")
            ca_name = str(getattr(cert, "ca", "") or "")
            tls_version = str(getattr(cert, "tls_version", "") or "")
            if cipher_suite:
                cipher_dist[cipher_suite[:30]] += 1
            if ca_name:
                ca_dist[ca_name[:25]] += 1
            if tls_version:
                tls_dist[tls_version] += 1

        vm = {
            "empty": cert_count == 0,
            "kpis": {
                "total_applications": scan_count, 
                "sites_surveyed": scan_count, 
                "active_certificates": cert_count,
                "weak_cryptography": weak_tls + weak_keys, 
                "certificate_issues": weak_tls + weak_keys,
            },
            "key_length_distribution": dict(key_dist) or {"No Data": 0},
            "cipher_usage": dict(cipher_dist.most_common(5)) or {"No Data": 0}, 
            "top_cas": dict(ca_dist.most_common(5)) or {"No Data": 0}, 
            "protocols": dict(tls_dist) or {"No Data": 0},
            "rows": [], 
            "weakness_heatmap": [{"x": "Weak TLS", "y": "Risk", "value": weak_tls}, {"x": "Weak Keys", "y": "Risk", "value": weak_keys}],
        }
    except Exception as e:
        vm = {"empty": True, "kpis": {"total_applications": 0, "sites_surveyed": 0, "active_certificates": 0, "weak_cryptography": 0, "certificate_issues": 0}}
        page_data = {"items": [], "total_count": 0, "has_next": False, "has_prev": False}
    return render_template("cbom_dashboard.html", vm=vm, page_data=page_data)


@app.route("/pqc-posture")
@login_required
def pqc_posture():
    """Build PQC posture with real quantum-safe readiness metrics."""
    from src.db import db_session
    from src.models import PQCClassification, Scan
    from sqlalchemy import func
    from collections import Counter
    
    try:
        items = (
            db_session.query(Scan)
            .filter(Scan.status == "complete")
            .order_by(Scan.started_at.desc())
            .all()
        )
        page_data = {
            "items": items,
            "total_count": len(items),
            "page": 1,
            "page_size": len(items),
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        }
        
        # Calculate PQC posture from scans
        scans = items
        pqc_counts = Counter()
        pqc_scores = []
        
        for scan in scans:
            raw_score = getattr(scan, "overall_pqc_score", 0)
            try:
                score = float(raw_score or 0)
            except (TypeError, ValueError):
                score = 0.0
            pqc_scores.append(score)
            
            if score >= 80:
                pqc_counts["Elite"] += 1
            elif score >= 60:
                pqc_counts["Standard"] += 1
            elif score >= 40:
                pqc_counts["Legacy"] += 1
            else:
                pqc_counts["Critical"] += 1
        
        avg_pqc_score = sum(pqc_scores) / len(pqc_scores) if pqc_scores else 0
        elite_count = pqc_counts.get("Elite", 0)
        standard_count = pqc_counts.get("Standard", 0)
        legacy_count = pqc_counts.get("Legacy", 0)
        critical_count = pqc_counts.get("Critical", 0)
        
        vm = {
            "empty": page_data["total_count"] == 0,
            "overall": {"elite": elite_count, "standard": standard_count, "legacy": legacy_count, "critical_apps": critical_count},
            "grade_counts": {"Elite": elite_count, "Standard": standard_count, "Legacy": legacy_count, "Critical": critical_count},
            "average_pqc_score": round(avg_pqc_score, 1),
            "status_distribution": dict(pqc_counts),
            "recommendations": [
                f"Total scanned targets: {len(scans)}",
                f"Average PQC readiness: {round(avg_pqc_score, 1)}%",
                f"Critical applications requiring remediation: {critical_count}",
            ],
            "support_rows": [],
            "risk_heatmap": [{"x": "PQC Grade", "y": grade, "value": pqc_counts.get(grade, 0)} for grade in ["Critical", "Legacy", "Standard", "Elite"]]
        }
    except Exception as e:
        vm = {
            "empty": True,
            "overall": {"elite": 0, "standard": 0, "legacy": 0, "critical_apps": 0},
            "grade_counts": {"Elite": 0, "Critical": 0, "Standard": 0},
            "status_distribution": {},
            "recommendations": ["Run scans to populate PQC posture."],
            "support_rows": [],
            "risk_heatmap": []
        }
        page_data = {"items": [], "total_count": 0, "has_next": False, "has_prev": False}
    return render_template("pqc_posture.html", vm=vm, page_data=page_data)


@app.route("/cyber-rating")
@login_required
def cyber_rating():
    """Build cyber rating with real enterprise compliance metrics."""
    from src.db import db_session
    from src.models import Scan
    from sqlalchemy import func
    from collections import Counter
    try:
        scan_pk = getattr(Scan, "id", None) or getattr(Scan, "scan_id")
        scan_count = db_session.query(func.count(scan_pk)).scalar() or 0
        items = (
            db_session.query(Scan)
            .filter(Scan.status == "complete")
            .order_by(Scan.started_at.desc())
            .all()
        )
        page_data = {
            "items": items,
            "total_count": len(items),
            "page": 1,
            "page_size": len(items),
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        }
        
        # Calculate enterprise-wide cyber rating
        scans = items
        scores = []
        tier_dist = Counter()
        
        for scan in scans:
            # Get available score field (multiple naming conventions)
            score = 50.0
            overall_pqc_score = getattr(scan, "overall_pqc_score", None)
            avg_compliance_score = getattr(scan, "average_compliance_score", None)
            try:
                if overall_pqc_score is not None:
                    score = float(overall_pqc_score)
                elif avg_compliance_score is not None:
                    score = float(avg_compliance_score)
            except (TypeError, ValueError):
                score = 50.0
            
            scores.append(score)
            
            # Classify into tier
            if score >= 850:
                tier_dist["Elite-PQC"] += 1
            elif score >= 600:
                tier_dist["Standard"] += 1
            elif score >= 350:
                tier_dist["Legacy"] += 1
            else:
                tier_dist["Critical"] += 1
        
        overall_score = int(sum(scores) / len(scores)) if scores else 0
        tier_labels = {0: "Critical", 1: "Legacy", 2: "Standard", 3: "Elite"}
        if overall_score >= 850:
            label = "Elite"
        elif overall_score >= 600:
            label = "Standard"
        elif overall_score >= 350:
            label = "Legacy"
        else:
            label = "Critical"
        
        vm = {
            "empty": scan_count == 0,
            "overall_score": overall_score,
            "label": label,
            "tier_counts": {"Critical": tier_dist.get("Critical", 0), "Legacy": tier_dist.get("Legacy", 0), "Standard": tier_dist.get("Standard", 0), "Elite-PQC": tier_dist.get("Elite-PQC", 0)},
            "tier_heatmap": [{"x": "Cyber Rating", "y": tier, "value": tier_dist.get(tier, 0)} for tier in ["Critical", "Legacy", "Standard", "Elite-PQC"]],
        }
    except Exception as e:
        vm = {"empty": True, "overall_score": 0, "label": "Unknown", "tier_counts": {"Critical": 0, "Legacy": 0, "Standard": 0, "Elite-PQC": 0}, "tier_heatmap": []}
        page_data = {"items": [], "total_count": 0, "has_next": False, "has_prev": False}
    return render_template("cyber_rating.html", vm=vm, page_data=page_data)


@app.route("/reporting")
@login_required
def reporting():
    from src.db import db_session
    from src.models import Scan
    from sqlalchemy import func
    try:
        scan_pk = getattr(Scan, "id", None) or getattr(Scan, "scan_id")
        scan_count = db_session.query(func.count(scan_pk)).scalar() or 0
        
        # Build real reporting metrics
        inv = _build_asset_inventory_view()
        
        from src.models import Certificate
        cert_count = db_session.query(func.count(Certificate.id)).scalar() or 0
        weak_certs = db_session.query(func.count(Certificate.id)).filter(
            Certificate.tls_version.in_(["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"])
        ).scalar() or 0
        
        scans = db_session.query(Scan).filter(Scan.status == "complete").all()
        pqc_scores = [float(getattr(s, 'overall_pqc_score', 0) or 50) for s in scans]
        avg_pqc_score = int(sum(pqc_scores) / len(pqc_scores)) if pqc_scores else 0
        
        unique_targets = db_session.query(func.count(func.distinct(Scan.target))).filter(Scan.status == "complete").scalar() or 0
        
        vm = {
            "summary": {
                "discovery": f"Targets: {unique_targets} | Complete Scans: {scan_count} | Assessed Endpoints: {len(scans)}",
                "pqc": f"Assessed endpoints: {len(scans)} | Average PQC Score: {avg_pqc_score}%",
                "cbom": f"Total certificates: {cert_count} | Weak cryptography: {weak_certs}",
                "cyber_rating": f"Average enterprise score: {avg_pqc_score}/100",
                "inventory": f"Assets: {inv.get('kpis', {}).get('total_assets', 0)} | Expiring: {inv.get('kpis', {}).get('expiring_certificates', 0)} | High Risk: {inv.get('kpis', {}).get('high_risk_assets', 0)}",
            },
            "empty": scan_count == 0,
        }
    except Exception as e:
        try:
            inv = _build_asset_inventory_view()
        except:
            inv = {"kpis": {"total_assets": 0, "expiring_certificates": 0, "high_risk_assets": 0}}
        
        vm = {
            "summary": {
                "discovery": "Targets: 0 | Complete Scans: 0 | Assessed Endpoints: 0",
                "pqc": "Assessed endpoints: 0 | Average PQC Score: 0%",
                "cbom": "Total certificates: 0 | Weak cryptography: 0",
                "cyber_rating": "Average enterprise score: 0/100",
                "inventory": f"Assets: {inv.get('kpis', {}).get('total_assets', 0)} | Expiring: {inv.get('kpis', {}).get('expiring_certificates', 0)} | High Risk: {inv.get('kpis', {}).get('high_risk_assets', 0)}",
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
            report = run_scan_pipeline(clean_target, ports, asset_class_hint=asset_class_hint)
            
            # Ensure persistence to both JSON and MySQL
            try:
                if db._db_available:
                    db.save_scan(report)
            except Exception as db_err:
                logger.warning(f"Failed to save scan to MySQL: {db_err}")
            
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
                    report = run_scan_pipeline(clean_target, ports, asset_class_hint=asset_class_hint)
                    
                    # Persist to both JSON and MySQL
                    try:
                        if db._db_available:
                            db.save_scan(report)
                    except Exception as db_err:
                        logger.warning(f"Failed to save scan to MySQL for {clean_target}: {db_err}")
                    
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
        report = run_scan_pipeline(clean_target)
        
        # Ensure persistence: save to both JSON and MySQL
        try:
            if db._db_available:
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



@app.route("/api/scans")
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
        return jsonify({"status": "success", "data": scans}), 200
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
    """Admin: revoke and reissue an API key for any user."""
    user = db.get_user_by_id(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))
    db.revoke_api_key(user_id)
    new_key = db.generate_api_key(user_id)
    if new_key:
        _audit("admin", "api_key_regen", "success", target_user_id=user_id,
               details={"username": user.get("username")})
        flash(f"New API key for {user.get('username')}: {new_key}", "api_key")
    else:
        _audit("admin", "api_key_regen", "failed", target_user_id=user_id)
        flash("Failed to regenerate API key.", "error")
    return redirect(url_for("admin_users"))


# ── Report Generation Engine ─────────────────────────────────────────

def _make_pdf_report(report_type: str, username: str, sections: list[str]) -> bytes:
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
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2.2 * cm,
        rightMargin=2.2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
        title=f"PNB Hackathon 2026 — {report_type}",
        author="QuantumShield Platform",
    )

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

    cb_rows = []
    cb_key_dist: dict[str, int] = {}
    cb_cipher_usage: dict[str, int] = {}
    cb_protocols: dict[str, int] = {}
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

    pqc_rows = []
    for scan in scan_store.values():
        if scan.get("status") != "complete":
            continue
        host = _host_from_target(str(scan.get("target", "")))
        for pqc in (scan.get("pqc_assessments") or []):
            score = int(pqc.get("pqc_score") or pqc.get("score") or 0)
            status = "Elite" if score >= 800 else ("Standard" if score >= 500 else ("Legacy" if score >= 300 else "Critical"))
            pqc_rows.append((host, str(score), status))

    cyber_rows = []
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
    _audit("report", "generate_pdf", "success", details={
        "report_type": report_type,
        "sections": sections,
        "username": username,
    })

    pdf_bytes = _make_pdf_report(report_type, username, sections)
    safe_type = "".join(c if c.isalnum() else "_" for c in report_type)[:40]
    filename = f"PNB_{safe_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"

    return Response(
        pdf_bytes,
        status=200,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
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

    schedule = {
        "id": uuid.uuid4().hex[:12],
        "created_by_id": str(getattr(current_user, "id", "")) or None,
        "created_by": getattr(current_user, "username", "unknown"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "enabled": _single(data.get("enabled", "true")).lower() not in ("false", "0", "off", ""),
        "report_type": _single(data.get("report_type", "Executive Summary Report"))[:120],
        "frequency": _single(data.get("frequency", "Weekly"))[:32],
        "assets": _single(data.get("assets", "All Assets"))[:256],
        "sections": data.get("sections") if isinstance(data.get("sections"), list) else [],
        "schedule_date": _single(data.get("schedule_date", ""))[:20],
        "schedule_time": _single(data.get("schedule_time", ""))[:10],
        "timezone": _single(data.get("timezone", "UTC"))[:64],
        "email_list": _single(data.get("email_list", ""))[:512],
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

@app.route("/recycle-bin")
@login_required
def recycle_bin():
    """Isolated dashboard for soft-deleted assets and scans."""
    from src.db import db_session
    from src.models import Asset, Scan
    try:
        deleted_assets = db_session.query(Asset).filter(Asset.is_deleted == True).all()
        deleted_scans = db_session.query(Scan).filter(Scan.is_deleted == True).all()
        vm = {
            "empty": not deleted_assets and not deleted_scans,
            "assets": deleted_assets,
            "scans": deleted_scans,
        }
    except Exception:
        vm = {"empty": True, "assets": [], "scans": []}
    return render_template("inventory.html", vm=vm)



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
