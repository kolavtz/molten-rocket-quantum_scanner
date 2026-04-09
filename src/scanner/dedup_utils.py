"""
dedup_utils
============

Shared helper for computing dedup algorithm, dedup value and dedup hash for
certificate ingestion. This centralises the logic so both the ORM path and the
raw-sql worker compute identical values.

The dedup value format follows existing conventions:
 - sha256: raw hex string (no prefix)
 - sha1: prefixed with "sha1:"
 - md5: prefixed with "md5:"

The dedup_hash is SHA-256 of "{asset_id}:{dedup_value}" (lowercase hex).
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional, Tuple


def compute_dedup_values(asset_id: int, cert_obj: Any) -> Tuple[Optional[str], str, Optional[str]]:
    """Compute (dedup_algorithm, dedup_value, dedup_hash) for a certificate.

    - asset_id: integer asset identifier used as part of dedup_hash input
    - cert_obj: object returned by TLSAnalyzer with attributes like
      `fingerprint_sha256` and `certificate_details` (dict)

    Returns a tuple: (algorithm_or_None, dedup_value_or_empty_string, dedup_hash_or_None)
    """
    dedup_algorithm: Optional[str] = None
    dedup_value: str = ""

    try:
        if cert_obj:
            # Prefer certificate SHA-256 fingerprint
            fp256 = getattr(cert_obj, "fingerprint_sha256", None) or (
                cert_obj.certificate_details.get("fingerprint_sha256")
                if getattr(cert_obj, "certificate_details", None) and isinstance(cert_obj.certificate_details, dict)
                else None
            )
            if fp256:
                dedup_algorithm = "sha256"
                dedup_value = str(fp256)
            else:
                # Fallback to public-key SHA-256
                pk_fp = None
                try:
                    pk_fp = (cert_obj.certificate_details.get("subject_public_key_info", {}) or {}).get("public_key_fingerprint_sha256")
                except Exception:
                    pk_fp = None
                if pk_fp:
                    dedup_algorithm = "sha256"
                    dedup_value = str(pk_fp)
                else:
                    # Try SHA-1 then MD5
                    try:
                        fp1 = cert_obj.certificate_details.get("fingerprint_sha1")
                    except Exception:
                        fp1 = None
                    if fp1:
                        dedup_algorithm = "sha1"
                        dedup_value = f"sha1:{str(fp1)}"
                    else:
                        try:
                            fpm = cert_obj.certificate_details.get("fingerprint_md5")
                        except Exception:
                            fpm = None
                        if fpm:
                            dedup_algorithm = "md5"
                            dedup_value = f"md5:{str(fpm)}"
    except Exception:
        # Conservative: any error computing dedup values should not crash ingestion
        dedup_algorithm = None
        dedup_value = ""

    if dedup_value:
        raw = f"{asset_id}:{dedup_value}"
        dedup_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    else:
        dedup_hash = None

    return dedup_algorithm, dedup_value, dedup_hash
