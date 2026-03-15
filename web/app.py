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
    default_limits=RATELIMIT_DEFAULT_LIMITS,  # type: ignore[arg-type]
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
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com https://unpkg.com; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "connect-src 'self'; "
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


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def forgot_password():
    """Email-based password reset flow."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

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


def _build_asset_inventory_view() -> dict:
    """Build asset inventory view — seeded + enriched from live scan store."""
    seed_assets = [
        {
            "asset_name": "pnb-banking-portal",
            "url": "https://banking.pnb.example",
            "ipv4": "203.0.113.10",
            "ipv6": "2001:db8:100::10",
            "type": "Web App",
            "owner": "IT",
            "risk": "High",
            "cert_status": "Expiring",
            "key_length": 2048,
            "last_scan": "2h ago",
        },
        {
            "asset_name": "pnb-api-gateway",
            "url": "https://api.pnb.example",
            "ipv4": "203.0.113.11",
            "ipv6": "2001:db8:100::11",
            "type": "API",
            "owner": "DevOps",
            "risk": "Critical",
            "cert_status": "Valid",
            "key_length": 2048,
            "last_scan": "28m ago",
        },
        {
            "asset_name": "pnb-payment-core",
            "url": "https://pay.pnb.example",
            "ipv4": "203.0.113.25",
            "ipv6": "",
            "type": "Server",
            "owner": "Infra",
            "risk": "Medium",
            "cert_status": "Valid",
            "key_length": 3072,
            "last_scan": "1d ago",
        },
        {
            "asset_name": "pnb-mobile-api",
            "url": "https://mobile-api.pnb.example",
            "ipv4": "203.0.113.30",
            "ipv6": "2001:db8:100::30",
            "type": "API",
            "owner": "IT",
            "risk": "Low",
            "cert_status": "Valid",
            "key_length": 4096,
            "last_scan": "4h ago",
        },
    ]

    # Merge live scans into asset list
    seen_targets: set[str] = {a["url"] for a in seed_assets}
    for scan in sorted(scan_store.values(),
                       key=lambda s: s.get("generated_at", ""), reverse=True):
        if scan.get("status") != "complete":
            continue
        target = scan.get("target", "")
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)
        overview = scan.get("overview") or {}
        score = overview.get("average_compliance_score", 500)
        risk = "Low" if score >= 700 else ("Medium" if score >= 400 else ("High" if score >= 200 else "Critical"))
        tls_results = scan.get("tls_results") or []
        key_length = 2048
        tls_ver = "TLS 1.2"
        cipher = "ECDHE-RSA-AES256-GCM-SHA384"
        if tls_results:
            first = tls_results[0]
            key_length = first.get("key_size") or first.get("key_length") or 2048
            tls_ver = first.get("tls_version") or "TLS 1.2"
            ciphers = first.get("cipher_suites") or []
            cipher = ciphers[0] if ciphers else cipher
        seed_assets.append({
            "asset_name": target,
            "url": f"https://{target}" if not target.startswith("http") else target,
            "ipv4": "",
            "ipv6": "",
            "type": "Web App",
            "owner": "IT",
            "risk": risk,
            "cert_status": "Valid",
            "key_length": key_length,
            "last_scan": scan.get("generated_at", "")[:16],
            "_live": True,
            "_tls_version": tls_ver,
            "_cipher_suite": cipher,
        })

    assets = seed_assets
    kpis = {
        "total_assets": len(assets),
        "public_web_apps": sum(1 for a in assets if a["type"] == "Web App"),
        "apis": sum(1 for a in assets if a["type"] == "API"),
        "servers": sum(1 for a in assets if a["type"] == "Server"),
        "expiring_certificates": sum(1 for a in assets if a["cert_status"] == "Expiring"),
        "high_risk_assets": sum(1 for a in assets if a["risk"] in {"Critical", "High"}),
    }
    from collections import Counter
    type_dist = dict(Counter(a["type"] for a in assets))
    risk_dist = dict(Counter(a["risk"] for a in assets))

    return {
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
        "certificate_expiry_timeline": {"0-30": 1, "30-60": 1, "60-90": 1, ">90": max(len(assets) - 3, 1)},
        "ip_version_breakdown": {"IPv4": 75, "IPv6": 25},
        "assets": assets,
        "nameserver_records": [
            {"hostname": "ns1.pnb.example", "type": "A", "ip": "203.0.113.53", "ipv6": "", "ttl": 3600},
            {"hostname": "ns2.pnb.example", "type": "AAAA", "ip": "", "ipv6": "2001:db8:53::2", "ttl": 3600},
        ],
        "crypto_overview": [
            {
                "asset": a.get("asset_name") or a.get("url", ""),
                "key_length": a.get("key_length", 2048),
                "cipher_suite": a.get("_cipher_suite", "ECDHE-RSA-AES256-GCM-SHA384"),
                "tls_version": a.get("_tls_version", "TLS 1.2"),
                "ca": "DigiCert",
                "last_scan": a.get("last_scan", ""),
            }
            for a in assets[:10]
        ],
    }


def _build_asset_discovery_view() -> dict:
    return {
        "overview": {"domains": 12, "ssl": 19, "ip_subnets": 24, "software": 35},
        "domains": [
            {"status": "New", "detection_date": "2026-03-15", "domain_name": "new-auth.pnb.example", "registration_date": "2026-03-10", "registrar": "MarkMonitor", "company": "PNB"},
            {"status": "Confirmed", "detection_date": "2026-03-14", "domain_name": "payments.pnb.example", "registration_date": "2023-04-09", "registrar": "CSC", "company": "PNB"},
        ],
        "ssl": [
            {"status": "New", "detection_date": "2026-03-15", "fingerprint": "AA:BB:CC:DD:11", "valid_from": "2026-02-01", "common_name": "payments.pnb.example", "company": "PNB", "ca": "DigiCert"},
            {"status": "False Positive", "detection_date": "2026-03-14", "fingerprint": "EF:12:45:AB:88", "valid_from": "2025-11-20", "common_name": "legacy.pnb.example", "company": "PNB", "ca": "Thawte"},
        ],
        "ip_subnets": [
            {"status": "Confirmed", "detection_date": "2026-03-15", "ip": "198.51.100.24", "ports": "443,8443", "subnet": "198.51.100.0/24", "asn": "AS64500", "netname": "PNB-EDGE", "location": "SG", "company": "PNB"},
            {"status": "New", "detection_date": "2026-03-13", "ip": "203.0.113.88", "ports": "443", "subnet": "203.0.113.0/24", "asn": "AS64501", "netname": "PNB-API", "location": "MY", "company": "PNB"},
        ],
        "software": [
            {"status": "New", "detection_date": "2026-03-15", "product": "nginx", "version": "1.25.5", "type": "WebServer", "port": 443, "host": "payments.pnb.example", "company": "PNB"},
            {"status": "Confirmed", "detection_date": "2026-03-15", "product": "OpenSSL", "version": "3.2.1", "type": "Crypto Library", "port": 443, "host": "api.pnb.example", "company": "PNB"},
        ],
    }


@app.route("/asset-inventory")
@login_required
def asset_inventory():
    return render_template("asset_inventory.html", vm=_build_asset_inventory_view())


@app.route("/asset-discovery")
@login_required
def asset_discovery():
    return render_template("asset_discovery.html", vm=_build_asset_discovery_view())


@app.route("/cbom-dashboard")
@login_required
def cbom_dashboard():
    """Build CBOM view — aggregates cipher/key/protocol data from live scans."""
    from collections import Counter

    seed_cipher = {
        "ECDHE-RSA-AES256-GCM-SHA384": 17,
        "ECDHE-ECDSA-AES256-GCM-SHA384": 11,
        "AES256-GCM-SHA384": 8,
        "AES128-GCM-SHA256": 13,
        "TLS_RSA_WITH_DES_CBC_SHA": 3,
    }
    seed_keys = {"4096": 16, "3078": 8, "2048": 21, "2044": 4, "others": 7}
    seed_protocols = {"TLS 1.3": 31, "TLS 1.2": 62, "TLS 1.1": 8, "TLS 1.0": 2}
    live_rows: list[dict] = []

    key_counter: Counter = Counter()
    cipher_counter: Counter = Counter()
    proto_counter: Counter = Counter()

    for scan in scan_store.values():
        if scan.get("status") != "complete":
            continue
        for tr in (scan.get("tls_results") or []):
            tls_ver = tr.get("tls_version") or "TLS 1.2"
            proto_counter[tls_ver] += 1
            key_sz = tr.get("key_size") or tr.get("key_length")
            if key_sz:
                key_counter[str(key_sz)] += 1
            for cs in (tr.get("cipher_suites") or []):
                if cs:
                    cipher_counter[cs] += 1
            live_rows.append({
                "application": scan.get("target", ""),
                "key_length": key_sz or 2048,
                "cipher": (tr.get("cipher_suites") or ["—"])[0],
                "ca": tr.get("issuer", {}).get("O", "Unknown") if isinstance(tr.get("issuer"), dict) else "Unknown",
            })

    # Merge live counters with seeds
    for k, v in key_counter.items():
        seed_keys[k] = seed_keys.get(k, 0) + v
    for c, v in cipher_counter.most_common(5):
        seed_cipher[c] = seed_cipher.get(c, 0) + v
    for p, v in proto_counter.items():
        seed_protocols[p] = seed_protocols.get(p, 0) + v

    seed_rows = [
        {"application": "pnb-banking-portal", "key_length": 2048, "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "ca": "DigiCert"},
        {"application": "pnb-mobile-api", "key_length": 4096, "cipher": "ECDHE-ECDSA-AES256-GCM-SHA384", "ca": "Let's Encrypt"},
        {"application": "legacy-gateway", "key_length": 1024, "cipher": "TLS_RSA_WITH_DES_CBC_SHA", "ca": "COMODO"},
    ]
    all_rows = seed_rows + live_rows

    total_apps = len({r["application"] for r in all_rows})
    vm = {
        "kpis": {
            "total_applications": total_apps,
            "sites_surveyed": max(41, total_apps),
            "active_certificates": max(103, total_apps * 2),
            "weak_cryptography": sum(1 for r in all_rows if int(r.get("key_length", 9999)) < 2048),
            "certificate_issues": 8,
        },
        "key_length_distribution": seed_keys,
        "cipher_usage": seed_cipher,
        "top_cas": {"DigiCert": 32, "Thawte": 8, "Let's Encrypt": 24, "COMODO": 12, "Other": 27},
        "protocols": seed_protocols,
        "rows": all_rows[:25],
    }
    return render_template("cbom_dashboard.html", vm=vm)


@app.route("/pqc-posture")
@login_required
def pqc_posture():
    """Build PQC posture view — aggregates PQC assessments from live scans."""
    seed_rows = [
        {"asset_name": "payments.pnb.example (203.0.113.25)", "pqc_support": True, "owner": "Infra", "exposure": "Internet", "tls": "ECC", "score": 860, "status": "Elite"},
        {"asset_name": "legacy-gateway.pnb.example (198.51.100.30)", "pqc_support": False, "owner": "IT", "exposure": "Internet", "tls": "RSA", "score": 390, "status": "Critical"},
        {"asset_name": "api.pnb.example (203.0.113.11)", "pqc_support": False, "owner": "DevOps", "exposure": "Internet", "tls": "RSA", "score": 620, "status": "Standard"},
    ]

    for scan in scan_store.values():
        if scan.get("status") != "complete":
            continue
        for pqc in (scan.get("pqc_assessments") or []):
            score = pqc.get("pqc_score") or pqc.get("score") or 500
            is_pqc = bool(pqc.get("pqc_ready") or pqc.get("is_pqc_ready") or score >= 700)
            status = "Elite" if score >= 700 else ("Standard" if score >= 400 else "Critical")
            seed_rows.append({
                "asset_name": f"{scan.get('target', '')}",
                "pqc_support": is_pqc,
                "owner": "IT",
                "exposure": "Internet",
                "tls": pqc.get("key_type", "RSA"),
                "score": score,
                "status": status,
            })

    elite = sum(1 for r in seed_rows if r["status"] == "Elite")
    standard = sum(1 for r in seed_rows if r["status"] == "Standard")
    legacy = sum(1 for r in seed_rows if r["status"] == "Legacy")
    critical = sum(1 for r in seed_rows if r["status"] == "Critical")
    total = max(len(seed_rows), 1)

    vm = {
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
        "support_rows": seed_rows[:30],
        "recommendations": [
            "Upgrade to TLS 1.3 with PQC",
            "Implement Kyber for Key Exchange",
            "Update Cryptographic Libraries",
            "Develop PQC Migration Plan",
        ],
    }
    return render_template("pqc_posture.html", vm=vm)


@app.route("/cyber-rating")
@login_required
def cyber_rating():
    """Build cyber rating — derives score from live scan compliance scores."""
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

    # Seed URL scores for display even with no live data
    seed_urls = [
        {"url": "https://banking.pnb.example", "pqc_score": 812},
        {"url": "https://api.pnb.example", "pqc_score": 655},
        {"url": "https://legacy-gateway.pnb.example", "pqc_score": 325},
    ]
    # Merge (live overrides seed by URL)
    live_url_set = {u["url"] for u in url_scores}
    merged_urls = url_scores + [u for u in seed_urls if u["url"] not in live_url_set]

    overall = round(sum(scores) / len(scores)) if scores else 755
    overall = max(0, min(overall, 1000))
    label = "Elite-PQC" if overall > 700 else ("Standard" if overall >= 400 else "Legacy")

    vm = {
        "overall_score": overall,
        "label": label,
        "url_scores": sorted(merged_urls, key=lambda u: u["pqc_score"], reverse=True)[:20],
    }
    return render_template("cyber_rating.html", vm=vm)


@app.route("/reporting")
@login_required
def reporting():
    vm = {
        "summary": {
            "discovery": "Domains/IPs/Subdomains monitored: 71 | Cloud assets: 19",
            "pqc": "Elite 42% | Standard 33% | Legacy 18% | Critical 7%",
            "cbom": "Total vulnerable crypto components: 11",
            "cyber_rating": "Tier 1 and 2 coverage improving across internet-facing assets",
            "inventory": "SSL certs: 103 | Software components: 35 | IoT devices: 4 | Login forms: 22",
        }
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

    # ── Section data keyed by module name ───────────────────────────
    section_data: dict[str, list] = {
        "Asset Inventory": [
            ("KPI", "Value"),
            ("Total Assets", "56"),
            ("Public Web Apps", "12"),
            ("APIs", "18"),
            ("Servers", "14"),
            ("Expiring Certificates", "5"),
            ("High Risk Assets", "9"),
        ],
        "Asset Discovery": [
            ("Category", "Count"),
            ("Domains discovered", "71"),
            ("SSL certificates", "103"),
            ("IP/Subnets", "244"),
            ("Software components", "35"),
            ("New (unconfirmed)", "6"),
        ],
        "CBOM": [
            ("Metric", "Value"),
            ("Total Applications", "56"),
            ("Sites Surveyed", "41"),
            ("Active Certificates", "103"),
            ("Weak Cryptography", "11"),
            ("Certificate Issues", "8"),
            ("Dominant TLS version", "TLS 1.2 (62%)"),
            ("Top Cipher Suite", "ECDHE-RSA-AES256-GCM-SHA384"),
        ],
        "PQC Posture": [
            ("Classification", "% / Count"),
            ("Elite-PQC Ready", "42%"),
            ("Standard", "33%"),
            ("Legacy", "18%"),
            ("Critical Apps", "7"),
        ],
        "Cyber Rating": [
            ("Tier", "Score Range", "Assets"),
            ("Elite-PQC (Tier 1)", ">700", "29"),
            ("Standard (Tier 2)", "400–700", "18"),
            ("Legacy (Tier 3)", "<400", "5"),
            ("Critical", "<200", "4"),
        ],
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
    try:
        with open(_SCHEDULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_schedules(schedules: list[dict]) -> None:
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
    return jsonify(_load_schedules())


# ── Main (WSGI-ready) ────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  \U0001f512 {app.import_name} \u2014 Quantum-Safe TLS Scanner")
    print(f"  \U0001f4e1 Running on https://{FLASK_HOST}:{FLASK_PORT}")
    print(f"{'='*60}\n")

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
