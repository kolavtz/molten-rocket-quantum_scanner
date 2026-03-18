"""
CryptoService layer for live SSL inspection metrics in QuantumShield.
Integrates directly with TLSAnalyzer for non-mock detail parsing.
"""

import socket
import ssl
from typing import Dict, Any, Optional

# Fallback or absolute lookup
try:
    from src.scanner.tls_analyzer import TLSAnalyzer, CertificateInfo
except ImportError:
    from scanner.tls_analyzer import TLSAnalyzer, CertificateInfo

class CryptoService:
    def __init__(self):
        self.analyzer = TLSAnalyzer()

    def inspect_endpoint(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Runs a live TLS scan and returns inspection mappings for landing views."""
        try:
            result = self.analyzer.analyze_endpoint(host, port)
            if not result.is_successful:
                return {"error": result.error or "TLS Handshake failed"}

            cert: Optional[CertificateInfo] = result.certificate
            if not cert:
                return {"error": "No Certificate retrieved"}

            return {
                "host": host,
                "port": port,
                "protocol_version": result.protocol_version or "Unknown",
                "cipher_suite": result.cipher_suite or "Unknown",
                "cipher_bits": result.cipher_bits,
                "key_exchange": result.key_exchange,
                # Certificate Subject Details
                "subject": {
                    "CN": cert.subject_cn or "<Not Part Of Certificate>",
                    "O": cert.subject_o or "<Not Part Of Certificate>",
                    "OU": cert.subject_ou or "<Not Part Of Certificate>"
                },
                # Certificate Issuer Details
                "issuer": {
                    "CN": cert.issuer_cn or "<Not Part Of Certificate>",
                    "O": cert.issuer_o or "<Not Part Of Certificate>",
                    "OU": cert.issuer_ou or "<Not Part Of Certificate>"
                },
                # Validity ranges
                "validity": {
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "days_remaining": cert.days_until_expiry,
                    "is_expired": cert.is_expired
                },
                "fingerprint_sha256": cert.fingerprint_sha256 or "Unknown",
                "key_type": cert.public_key_type or "Unknown",
                "key_size": cert.public_key_bits or 0
            }

        except Exception as e:
            return {"error": f"Live Inspection failed: {str(e)}"}
