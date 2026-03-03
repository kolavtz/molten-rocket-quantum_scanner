"""
Recommendation Engine Module

Provides actionable, server-specific migration guidance for endpoints
that are not quantum-safe, including Nginx, Apache, and cloud ALB
configuration snippets.

Classes:
    RecommendationEngine — generates migration recommendations.
"""

from __future__ import annotations

from typing import Any, Dict, List


class RecommendationEngine:
    """Generates server-specific PQC migration recommendations.

    Usage::

        engine = RecommendationEngine()
        recs = engine.get_recommendations(validation_result)
    """

    # ------------------------------------------------------------------
    # Migration templates
    # ------------------------------------------------------------------

    NGINX_TLS13_CONFIG = """# Nginx — Enable TLS 1.3 with PQC-ready cipher suites
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
ssl_prefer_server_ciphers off;
ssl_conf_command Groups X25519MLKEM768:X25519:secp384r1;"""

    APACHE_TLS13_CONFIG = """# Apache — Enable TLS 1.3
SSLProtocol -all +TLSv1.3
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:secp384r1"""

    CLOUD_ALB_GUIDANCE = """# AWS ALB — Quantum-safe cipher policy
# Use the 'ELBSecurityPolicy-TLS13-1-3-2021-06' or later policy
# Enable X25519MLKEM768 group in the ALB listener configuration
# Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/"""

    HAPROXY_CONFIG = """# HAProxy — TLS 1.3 with PQC groups
bind *:443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1
ssl-default-bind-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
ssl-default-bind-options ssl-min-ver TLSv1.3
ssl-default-bind-curves X25519MLKEM768:X25519:secp384r1"""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_recommendations(
        self, validation_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Return a list of actionable recommendations.

        Each recommendation dict contains:
        - ``priority`` (1–5, 1 = highest)
        - ``title``
        - ``description``
        - ``server_configs`` — dict mapping server name to config snippet
        - ``effort`` — estimated effort ("Low", "Medium", "High")
        - ``impact`` — security impact ("Critical", "High", "Medium")
        """
        recs: List[Dict[str, Any]] = []
        findings = validation_result.get("findings", [])
        label = validation_result.get("label", "Non-Compliant")

        # ── Key exchange recommendation ──
        kex_findings = [f for f in findings if f.get("category") == "key_exchange" and f.get("severity") in ("CRITICAL", "HIGH")]
        if kex_findings:
            recs.append({
                "priority": 1,
                "title": "Migrate to Post-Quantum Key Exchange",
                "description": (
                    "Replace current key exchange mechanism with ML-KEM-768 "
                    "(FIPS 203). Use hybrid X25519+ML-KEM-768 as a "
                    "transitional step for backward compatibility."
                ),
                "server_configs": {
                    "Nginx (OpenSSL 3.5+)": self.NGINX_TLS13_CONFIG,
                    "Apache (OpenSSL 3.5+)": self.APACHE_TLS13_CONFIG,
                    "HAProxy": self.HAPROXY_CONFIG,
                    "AWS ALB": self.CLOUD_ALB_GUIDANCE,
                },
                "effort": "Medium",
                "impact": "Critical",
                "timeline": "2-4 weeks",
            })

        # ── Protocol upgrade ──
        proto_findings = [f for f in findings if f.get("category") == "protocol" and f.get("severity") in ("CRITICAL", "MEDIUM")]
        if proto_findings:
            recs.append({
                "priority": 2,
                "title": "Upgrade to TLS 1.3",
                "description": (
                    "TLS 1.3 is required for PQC cipher suites and provides "
                    "improved security with mandatory forward secrecy. "
                    "Disable TLS 1.0, 1.1, and consider deprecating 1.2."
                ),
                "server_configs": {
                    "Nginx": "ssl_protocols TLSv1.3;\n# Optionally keep TLSv1.2 for legacy clients:\n# ssl_protocols TLSv1.2 TLSv1.3;",
                    "Apache": "SSLProtocol -all +TLSv1.3",
                },
                "effort": "Low",
                "impact": "High",
                "timeline": "1-2 weeks",
            })

        # ── Certificate replacement ──
        cert_findings = [f for f in findings if f.get("category") == "certificate" and f.get("severity") in ("CRITICAL", "HIGH")]
        if cert_findings:
            recs.append({
                "priority": 3,
                "title": "Obtain PQC-Signed Certificate",
                "description": (
                    "Replace current RSA/ECDSA certificate with a certificate "
                    "signed using ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205). "
                    "Contact your CA for PQC certificate availability."
                ),
                "server_configs": {
                    "OpenSSL (generate PQC key)": (
                        "# Generate ML-DSA-65 private key\n"
                        "openssl genpkey -algorithm mldsa65 -out server_pqc.key\n"
                        "# Generate CSR\n"
                        "openssl req -new -key server_pqc.key -out server_pqc.csr\n"
                        "# Self-sign (for testing)\n"
                        "openssl x509 -req -in server_pqc.csr -signkey server_pqc.key -out server_pqc.crt"
                    ),
                },
                "effort": "High",
                "impact": "High",
                "timeline": "4-8 weeks",
            })

        # ── General best practices ──
        if label != "PQC Ready":
            recs.append({
                "priority": 4,
                "title": "Implement Crypto Agility",
                "description": (
                    "Design systems to easily swap cryptographic algorithms "
                    "without major code changes. This ensures smooth future "
                    "transitions as PQC standards evolve."
                ),
                "server_configs": {},
                "effort": "Medium",
                "impact": "Medium",
                "timeline": "Ongoing",
            })

            recs.append({
                "priority": 5,
                "title": "Establish PQC Migration Timeline",
                "description": (
                    "Create a phased migration plan aligned with NIST's 2035 "
                    "deadline for deprecating quantum-vulnerable algorithms. "
                    "Prioritize high-value endpoints handling financial data."
                ),
                "server_configs": {},
                "effort": "Low",
                "impact": "Critical",
                "timeline": "Start immediately",
            })

        return sorted(recs, key=lambda r: r.get("priority", 99))
