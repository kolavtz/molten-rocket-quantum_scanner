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

mail = Mail(app)
csrf = CSRFProtect(app)
talisman = Talisman(app, content_security_policy=CSP_CONFIG, force_https=FORCE_HTTPS)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=RATELIMIT_DEFAULT_LIMITS,
    storage_uri=RATELIMIT_STORAGE_URI,
)

SCAN_ROLES = {"Admin", "Manager", "SingleScan"}
BULK_SCAN_ROLES = {"Admin", "Manager"}
ADMIN_PANEL_ROLES = {"Admin"}
ALL_APP_ROLES = {"Admin", "Manager", "SingleScan", "Viewer"}

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
                return redirect(url_for('index'))
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
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
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


def run_scan_pipeline(target: str, ports: list[int] | None = None) -> dict:
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
                    tls_results.append(result.to_dict())
        else:
            # Last resort: direct TLS analysis on port 443
            analyzer = TLSAnalyzer()
            tls_result = analyzer.analyze_endpoint(target, 443)
            if tls_result.is_successful:
                tls_results = [tls_result.to_dict()]
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
                tls_results.append(result.to_dict())

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
    report["scan_id"] = scan_id
    report["target"] = target
    report["status"] = "complete"
    report["tls_results"] = tls_results
    report["pqc_assessments"] = pqc_dicts
    report["recommendations_detailed"] = recommendations
    report["discovered_services"] = discovered_services

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

    # Store in memory
    scan_store[scan_id] = report

    return report


# ── Routes ───────────────────────────────────────────────────────────


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """Simple login page."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user_data = db.get_user_by_username(username)
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
            flash("Account temporarily locked due to repeated failed login attempts. Please try again later.", "error")
            return render_template("login.html")

        if user_data and check_password_hash(user_data["password_hash"], password):
            db.mark_login_success(user_data["id"])
            user = User(user_data)
            session.clear()
            login_user(user)
            _audit("auth", "login_success", "success", target_user_id=user_data["id"], details={"role": user.role})
            if user_data.get("must_change_password"):
                token = db.create_password_setup_token(user_data["id"], expires_hours=2)
                if token:
                    _audit("auth", "password_change_required", "success", target_user_id=user_data["id"], details={"reason": "must_change_password"})
                    flash("Please set a new password before continuing.", "warning")
                    return redirect(url_for("setup_password", token=token))
            return redirect(url_for('index'))
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
            flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Logout current user."""
    _audit("auth", "logout", "success")
    logout_user()
    session.clear()
    return redirect(url_for('login'))


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


@app.route("/")
@login_required
def index():
    """Scanner dashboard with enterprise metrics, scan form, and recent results."""
    recent_scans = sorted(
        list(scan_store.values()),
        key=lambda s: s.get("generated_at", ""),
        reverse=True,
    )[:10]

    # Calculate Enterprise Aggregate Metrics
    enterprise_metrics = {
        "total_assets": 0,
        "quantum_safe": 0,
        "quantum_vulnerable": 0,
        "total_score": 0,
        "scan_count": 0,
        "avg_score": 0,
        "critical_findings": 0,
    }

    for scan in scan_store.values():
        if scan.get("status") != "complete" or not scan.get("overview"):
            continue
        
        overview = scan["overview"]
        enterprise_metrics["scan_count"] += 1
        enterprise_metrics["total_assets"] += overview.get("total_assets", 0)
        enterprise_metrics["quantum_safe"] += overview.get("quantum_safe", 0)
        enterprise_metrics["quantum_vulnerable"] += overview.get("quantum_vulnerable", 0)
        enterprise_metrics["total_score"] += overview.get("average_compliance_score", 0)
        
        # Count critical findings
        for finding in scan.get("findings", []):
            if isinstance(finding, dict) and finding.get("severity", "").upper() == "CRITICAL":
                enterprise_metrics["critical_findings"] += 1

    if enterprise_metrics["scan_count"] > 0:
        enterprise_metrics["avg_score"] = round(
            enterprise_metrics["total_score"] / enterprise_metrics["scan_count"]
        )

    return render_template(
        "index.html", 
        recent_scans=recent_scans, 
        enterprise_metrics=enterprise_metrics
    )


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
        return redirect(url_for("index"))
        
    # Enforce advanced RBAC
    is_bulk = (csv_file and csv_file.filename) or len(targets) > 1
    if is_bulk and current_user.role not in BULK_SCAN_ROLES:
        _audit("scan", "bulk_scan_denied", "denied", details={"role": current_user.role, "target_count": len(targets)})
        flash("Your role allows single-target scans only.", "error")
        return redirect(url_for("index"))

    try:
        if len(targets) == 1:
            # Single scan: redirect directly to results page
            host, ports = targets[0]
            clean_target, _ = sanitize_target(host)
            report = run_scan_pipeline(clean_target, ports)
            _audit("scan", "single_scan", "success", target_scan_id=report.get("scan_id"), details={"target": clean_target})
            return redirect(url_for("results", scan_id=report.get("scan_id", "")))
        else:
            # Bulk scan: run all and redirect to dashboard
            for host, ports in targets:
                try:
                    clean_target, _ = sanitize_target(host)
                    report = run_scan_pipeline(clean_target, ports)
                    _audit("scan", "bulk_scan_item", "success", target_scan_id=report.get("scan_id"), details={"target": clean_target})
                except Exception:
                    continue  # skip invalid targets in bulk mode

            _audit("scan", "bulk_scan", "success", details={"target_count": len(targets)})
            return redirect(url_for("index"))

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



# ── Main ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  \U0001f512 {app.import_name} \u2014 Quantum-Safe TLS Scanner")
    print(f"  \U0001f4e1 Running on https://{FLASK_HOST}:{FLASK_PORT}")
    print(f"{'='*60}\n")

    # Prefer mkcert-generated trusted certs (no browser warning)
    _cert_file = os.path.join(BASE_DIR, "certs", "cert.pem")
    _key_file  = os.path.join(BASE_DIR, "certs", "key.pem")
    if os.path.exists(_cert_file) and os.path.exists(_key_file):
        _ssl_ctx = (_cert_file, _key_file)
        print("  \u2705 Using mkcert trusted SSL certificate (no browser warnings)")
    else:
        _ssl_ctx = "adhoc"
        print("  \u26a0  No certs/ dir found - using adhoc self-signed cert (browser will warn)")
        print("     To fix, run these commands once:")
        print("       mkcert -install")
        print("       mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1")

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=DEBUG,
        ssl_context=_ssl_ctx,
    )
