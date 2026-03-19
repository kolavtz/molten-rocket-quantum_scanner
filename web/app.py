"""
Quantum-Safe TLS Scanner — Flask Web Application

Routes:
    GET  /            → Scanner dashboard
    POST /scan        → Run scan pipeline
    GET  /results/<id>→ View scan results
    GET  /cbom/<id>   → Download CBOM JSON
    GET  /api/scan    → REST API endpoint
"""

from __future__ import annotations

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

# --- Start Automated Scan Background Scheduler ---
try:
    from src.scheduler import start_scheduler
    start_scheduler()
except Exception as e:
    app.logger.error(f"Failed to start automated scan scheduler: {e}")


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
_db_available = db.init_db()
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

    # 11. Save to MySQL (redundant copy)
    db.save_scan(report)
    db.save_cbom(scan_id, cbom_dict)
    db.save_dns_records(scan_id, dns_records)

    # Store in memory
    scan_store[scan_id] = report

    return report


# ── Routes ───────────────────────────────────────────────────────────

@app.route("/")
def root_index():
    """Redirects absolute root to the Main Dashboard."""
    return redirect(url_for('quantumshield_dashboard.dashboard_home'))



@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
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
    """Build inventory view-model from live scans only (no seed fallback)."""
    from collections import Counter
    import ipaddress

    assets: list[dict] = []
    nameserver_records: list[dict] = []
    crypto_overview: list[dict] = []
    asset_locations: list[dict] = []
    certificate_inventory: list[dict] = []
    cert_bucket = Counter({"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0})

    for scan in db.list_scans(limit=100):
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

        row = {
            "asset_name": host,
            "url": target if str(target).startswith("http") else f"https://{host}",
            "ipv4": ipv4,
            "ipv6": ipv6,
            "type": kind,
            "asset_class": str(scan.get("asset_class") or "Other"),
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
            "last_scan": row["last_scan"],
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
        edges.append({"from": src, "to": dst})

    for scan in db.list_scans(limit=100):
        if scan.get("status") != "complete" and not include_in_progress:
            continue

        target = str(scan.get("target", "")).strip()
        host = _host_from_target(target)
        if not host:
            continue

        detection_date = _iso_date(str(scan.get("generated_at", "")))
        add_node(f"domain:{host}", host, "domain", f"Domain · {host}")

        domains.append(
            {
                "status": "Confirmed" if scan.get("status") == "complete" else "New",
                "detection_date": detection_date,
                "domain_name": host,
                "registration_date": "",
                "registrar": "",
                "company": "PNB",
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
                            "company": "PNB",
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
                        "company": "PNB",
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
                    "company": "PNB",
                    "ca": issuer.get("O") or issuer.get("CN") or "Unknown",
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
    return render_template("asset_inventory.html", vm=_build_asset_inventory_view())


@app.route("/asset-discovery")
@login_required
def asset_discovery():
    return render_template("asset_discovery.html", vm=_build_asset_discovery_view())


@app.route("/api/discovery-graph")
@login_required
def discovery_graph_payload():
    """Realtime discovery graph payload for incremental frontend updates."""
    vm = _build_asset_discovery_view(include_in_progress=True)
    return jsonify(vm.get("graph_payload", {"nodes": [], "edges": [], "updated_at": ""}))


@app.route("/cbom-dashboard")
@login_required
def cbom_dashboard():
    """Build CBOM view using live cryptographic telemetry only."""
    from collections import Counter

    key_counter: Counter = Counter()
    cipher_counter: Counter = Counter()
    proto_counter: Counter = Counter()
    ca_counter: Counter = Counter()
    rows: list[dict] = []

    for scan in scan_store.values():
        if scan.get("status") != "complete":
            continue
        app_name = _host_from_target(str(scan.get("target", ""))) or str(scan.get("target", ""))
        for tr in (scan.get("tls_results") or []):
            tls_ver = str(tr.get("tls_version") or "Unknown")
            proto_counter[tls_ver] += 1
            key_sz = tr.get("key_size") or tr.get("key_length") or 0
            if key_sz:
                key_counter[str(key_sz)] += 1
            ciphers = tr.get("cipher_suites") or []
            for cs in ciphers:
                if cs:
                    cipher_counter[str(cs)] += 1
            issuer = tr.get("issuer") if isinstance(tr.get("issuer"), dict) else {}
            ca_name = issuer.get("O") or issuer.get("CN") or "Unknown"
            ca_counter[str(ca_name)] += 1
            rows.append(
                {
                    "application": app_name,
                    "key_length": key_sz,
                    "cipher": ciphers[0] if ciphers else "Unknown",
                    "ca": ca_name,
                }
            )

    weak_keys = sum(v for k, v in key_counter.items() if str(k).isdigit() and int(k) < 2048)
    weak_protocols = sum(v for p, v in proto_counter.items() if p in {"TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"})
    weak_ciphers = sum(v for c, v in cipher_counter.items() if "DES" in c or "RC4" in c or "MD5" in c)

    total_apps = len({r["application"] for r in rows})
    vm = {
        "empty": len(rows) == 0,
        "kpis": {
            "total_applications": total_apps,
            "sites_surveyed": total_apps,
            "active_certificates": len(rows),
            "weak_cryptography": weak_keys + weak_protocols + weak_ciphers,
            "certificate_issues": weak_protocols,
        },
        "key_length_distribution": dict(key_counter),
        "cipher_usage": dict(cipher_counter.most_common(10)),
        "top_cas": dict(ca_counter.most_common(10)),
        "protocols": dict(proto_counter),
        "rows": rows[:50],
        "weakness_heatmap": [
            {"x": "Key Length", "y": "Weak", "value": weak_keys},
            {"x": "Protocol", "y": "Weak", "value": weak_protocols},
            {"x": "Cipher", "y": "Weak", "value": weak_ciphers},
            {"x": "Key Length", "y": "Strong", "value": max(len(rows) - weak_keys, 0)},
            {"x": "Protocol", "y": "Strong", "value": max(len(rows) - weak_protocols, 0)},
            {"x": "Cipher", "y": "Strong", "value": max(len(rows) - weak_ciphers, 0)},
        ],
    }
    return render_template("cbom_dashboard.html", vm=vm)


@app.route("/pqc-posture")
@login_required
def pqc_posture():
    """Build PQC posture from live assessments only."""
    support_rows: list[dict] = []

    for scan in scan_store.values():
        if scan.get("status") != "complete":
            continue
        host = _host_from_target(str(scan.get("target", ""))) or str(scan.get("target", ""))
        pqc_list = scan.get("pqc_assessments") or []
        if not pqc_list:
            continue
        for pqc in pqc_list:
            score = int(pqc.get("pqc_score") or pqc.get("score") or 0)
            is_pqc = bool(pqc.get("pqc_ready") or pqc.get("is_pqc_ready") or score >= 700)
            if score >= 800:
                status = "Elite"
            elif score >= 500:
                status = "Standard"
            elif score >= 300:
                status = "Legacy"
            else:
                status = "Critical"
            support_rows.append(
                {
                    "asset_name": host,
                    "pqc_support": is_pqc,
                    "owner": "Infra",
                    "exposure": "Internet",
                    "tls": str(pqc.get("key_type") or "Unknown"),
                    "score": score,
                    "status": status,
                }
            )

    elite = sum(1 for r in support_rows if r["status"] == "Elite")
    standard = sum(1 for r in support_rows if r["status"] == "Standard")
    legacy = sum(1 for r in support_rows if r["status"] == "Legacy")
    critical = sum(1 for r in support_rows if r["status"] == "Critical")
    total = max(len(support_rows), 1)

    recommendations = []
    if critical > 0:
        recommendations.append("Upgrade critical legacy endpoints to TLS 1.3 with hybrid-PQC key exchange.")
    if legacy > 0:
        recommendations.append("Prioritize RSA-only services for Kyber-ready TLS stack migration.")
    if standard > 0:
        recommendations.append("Increase modern key sizes and rotate certificates to PQC-compatible profiles.")
    if not recommendations:
        recommendations.append("No immediate PQC remediation required. Maintain continuous scanning cadence.")

    vm = {
        "empty": len(support_rows) == 0,
        "overall": {
            "elite": round(elite * 100 / total),
            "standard": round(standard * 100 / total),
            "legacy": round(legacy * 100 / total),
            "critical_apps": critical,
        },
        "grade_counts": {"Elite": elite, "Critical": critical, "Standard": standard},
        "status_distribution": {
            "Elite-PQC Ready": round(elite * 100 / total),
            "Standard": round(standard * 100 / total),
            "Legacy": round(legacy * 100 / total),
            "Critical": round(critical * 100 / total),
        },
        "support_rows": support_rows[:50],
        "recommendations": recommendations,
        "risk_heatmap": [
            {"x": "Protocol", "y": "High", "value": critical},
            {"x": "Protocol", "y": "Moderate", "value": legacy},
            {"x": "Protocol", "y": "Safe", "value": elite + standard},
            {"x": "Key Exchange", "y": "High", "value": sum(1 for r in support_rows if r["tls"].upper() == "RSA")},
            {"x": "Key Exchange", "y": "Moderate", "value": sum(1 for r in support_rows if r["tls"].upper() == "ECC")},
            {"x": "Key Exchange", "y": "Safe", "value": sum(1 for r in support_rows if "PQC" in r["tls"].upper() or "KYBER" in r["tls"].upper())},
        ],
    }
    return render_template("pqc_posture.html", vm=vm)


@app.route("/cyber-rating")
@login_required
def cyber_rating():
    """Build cyber rating from live compliance scores only."""
    scores: list[int] = []
    url_scores: list[dict] = []

    for scan in sorted(scan_store.values(),
                       key=lambda s: s.get("generated_at", ""), reverse=True):
        if scan.get("status") != "complete":
            continue
        overview = scan.get("overview") or {}
        raw = overview.get("average_compliance_score") or 0
        # Normalise 0-100 score to 0-1000 range if needed
        normalized = min(int(raw * 10) if raw <= 100 else int(raw), 1000)
        scores.append(normalized)
        url_scores.append({
            "url": f"https://{scan.get('target', '')}" if not str(scan.get("target", "")).startswith("http") else scan.get("target", ""),
            "pqc_score": normalized,
        })

    overall = round(sum(scores) / len(scores)) if scores else 0
    overall = max(0, min(overall, 1000))
    label = "Elite-PQC" if overall > 700 else ("Standard" if overall >= 400 else "Legacy")

    tier_counts = {
        "Critical": sum(1 for s in scores if s < 200),
        "Legacy": sum(1 for s in scores if 200 <= s < 400),
        "Standard": sum(1 for s in scores if 400 <= s <= 700),
        "Elite-PQC": sum(1 for s in scores if s > 700),
    }

    heatmap = []
    for label_name, min_score, max_score in [
        ("Critical", 0, 199),
        ("Legacy", 200, 399),
        ("Standard", 400, 700),
        ("Elite-PQC", 701, 1000),
    ]:
        band_scores = [s for s in scores if min_score <= s <= max_score]
        heatmap.append({"x": label_name, "y": "Volume", "value": len(band_scores)})
        heatmap.append({"x": label_name, "y": "Avg", "value": round(sum(band_scores) / len(band_scores)) if band_scores else 0})

    vm = {
        "empty": len(url_scores) == 0,
        "overall_score": overall,
        "label": label,
        "url_scores": sorted(url_scores, key=lambda u: u["pqc_score"], reverse=True)[:50],
        "tier_counts": tier_counts,
        "tier_heatmap": heatmap,
    }
    return render_template("cyber_rating.html", vm=vm)


@app.route("/reporting")
@login_required
def reporting():
    inv = _build_asset_inventory_view()
    dis = _build_asset_discovery_view()

    pqc_rows = []
    for scan in scan_store.values():
        if scan.get("status") == "complete":
            pqc_rows.extend(scan.get("pqc_assessments") or [])

    weak_components = 0
    for scan in scan_store.values():
        if scan.get("status") != "complete":
            continue
        for tr in (scan.get("tls_results") or []):
            key_len = int(tr.get("key_size") or tr.get("key_length") or 0)
            if key_len and key_len < 2048:
                weak_components += 1
            if (tr.get("tls_version") or "") in {"TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"}:
                weak_components += 1

    cyber_scores = []
    for scan in scan_store.values():
        if scan.get("status") != "complete":
            continue
        overview = scan.get("overview") or {}
        raw = overview.get("average_compliance_score") or 0
        score = min(int(raw * 10) if raw <= 100 else int(raw), 1000)
        cyber_scores.append(score)

    vm = {
        "summary": {
            "discovery": f"Domains: {dis['overview']['domains']} | SSL: {dis['overview']['ssl']} | IP/Subnets: {dis['overview']['ip_subnets']} | Software: {dis['overview']['software']}",
            "pqc": f"Assessed endpoints: {len(pqc_rows)}",
            "cbom": f"Total vulnerable crypto components: {weak_components}",
            "cyber_rating": f"Average enterprise score: {round(sum(cyber_scores) / len(cyber_scores)) if cyber_scores else 0}/1000",
            "inventory": f"Assets: {inv['kpis']['total_assets']} | Expiring certs: {inv['kpis']['expiring_certificates']} | High risk assets: {inv['kpis']['high_risk_assets']}",
        },
        "empty": len(scan_store) == 0,
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
            _audit("scan", "single_scan", "success", target_scan_id=report.get("scan_id"), details={"target": clean_target})
            return redirect(url_for("results", scan_id=report.get("scan_id", "")))
        else:
            # Bulk scan: run all and redirect to dashboard
            for host, ports in targets:
                try:
                    clean_target, _ = sanitize_target(host)
                    report = run_scan_pipeline(clean_target, ports, asset_class_hint=asset_class_hint)
                    _audit("scan", "bulk_scan_item", "success", target_scan_id=report.get("scan_id"), details={"target": clean_target})
                except Exception:
                    continue  # skip invalid targets in bulk mode

            _audit("scan", "bulk_scan", "success", details={"target_count": len(targets)})
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
        _audit("scan", "download_cbom", "success", target_scan_id=scan_id, details={"source": "disk"})
        return send_file(
            cbom_path,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"cbom_{scan_id}.json",
        )
    # Fallback: try MySQL
    cbom_data = db.get_cbom(scan_id)
    if cbom_data:
        _audit("scan", "download_cbom", "success", target_scan_id=scan_id, details={"source": "database"})
        return jsonify(cbom_data)
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
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500



@app.route("/api/scans")
@csrf.exempt
@require_api_key
def api_list_scans():
    """List all stored scan results. Requires X-API-Key header."""
    from flask import g as _g
    api_user = _g.api_user
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
    return jsonify(scans)


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

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  \U0001f512 {app.import_name} \u2014 Quantum-Safe TLS Scanner")
    print(f"  \U0001f4e1 Running on https://{FLASK_HOST}:{FLASK_PORT}")
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
            print("  \u2705 Using mkcert trusted SSL certificate (no browser warnings)")
        else:
            _ssl_ctx = "adhoc"
            print("  \u26a0  No certs/ dir found - using adhoc self-signed cert (browser will warn)")
            print("     To fix, run:  mkcert -install && mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1")

        app.run(host=FLASK_HOST, port=FLASK_PORT, debug=True, ssl_context=_ssl_ctx)
    else:
        # Production mode: use Waitress (Windows-compatible WSGI server)
        try:
            from waitress import serve as waitress_serve  # type: ignore
            print("  \u2705 Production mode — Waitress WSGI server")
            if _has_certs:
                print(f"  \u2705 TLS certs loaded from certs/")
            else:
                print("  \u26a0  No certs/ dir — running plain HTTP on Waitress")
                print("     Tip: put a reverse proxy (nginx/caddy) in front for HTTPS in production")
            # Waitress does not natively handle SSL — use a reverse proxy for HTTPS.
            # For dev convenience with certs, fall back to Flask's ssl_context.
            if _has_certs:
                # Use Flask's dev server with certs for now (Waitress + SSL needs a proxy)
                app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, ssl_context=(_cert_file, _key_file))
            else:
                waitress_serve(app, host=FLASK_HOST, port=int(FLASK_PORT), threads=8)
        except ImportError:
            print("  \u26a0  Waitress not installed — falling back to Flask dev server")
            print("     Install with: pip install waitress")
            app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, ssl_context="adhoc")
