"""
CycloneDX Generator Module

Converts internal CBOM data into valid CycloneDX 1.6 JSON format for
industry-standard interoperability.  Uses the cyclonedx-python-lib
library when available, with a pure-dict fallback.

Classes:
    CycloneDXGenerator — produces CycloneDX-format JSON from a CBOM.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import APP_NAME, APP_VERSION, CBOM_SPEC_VERSION

# Try cyclonedx library; fall back to manual JSON if not installed
try:
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model import Property
    from cyclonedx.output.json import JsonV1Dot6
    HAS_CYCLONEDX_LIB = True
except ImportError:
    HAS_CYCLONEDX_LIB = False


class CycloneDXGenerator:
    """Produces CycloneDX 1.6 JSON output from a CBOM.

    Usage::

        gen = CycloneDXGenerator()
        json_str = gen.generate(cbom.to_dict())
        gen.export_json(cbom.to_dict(), "scan_results/cbom.json")
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, cbom_dict: Dict[str, Any]) -> str:
        """Return CycloneDX 1.6 JSON string from *cbom_dict*.

        Falls back to a hand-crafted dict if ``cyclonedx-python-lib``
        is not installed.
        """
        if HAS_CYCLONEDX_LIB:
            return self._generate_with_lib(cbom_dict)
        return self._generate_manual(cbom_dict)

    def export_json(
        self, cbom_dict: Dict[str, Any], path: str
    ) -> str:
        """Write CycloneDX JSON to *path* and return the JSON string."""
        content = self.generate(cbom_dict)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return content

    # ------------------------------------------------------------------
    # Library-based generation
    # ------------------------------------------------------------------

    def _generate_with_lib(self, cbom_dict: Dict[str, Any]) -> str:
        """Use ``cyclonedx-python-lib`` for standards-compliant output."""
        bom = Bom()

        for asset in cbom_dict.get("assets", []):
            props = [
                Property(name="quantum-safe:protocol", value=asset.get("protocol_version", "")),
                Property(name="quantum-safe:cipher_suite", value=asset.get("cipher_suite", "")),
                Property(name="quantum-safe:key_exchange", value=asset.get("key_exchange", "")),
                Property(name="quantum-safe:cipher_bits", value=str(asset.get("cipher_bits", 0))),
                Property(name="quantum-safe:cert_subject", value=asset.get("cert_subject", "")),
                Property(name="quantum-safe:cert_issuer", value=asset.get("cert_issuer", "")),
                Property(name="quantum-safe:cert_public_key_type", value=asset.get("cert_public_key_type", "")),
                Property(name="quantum-safe:cert_public_key_bits", value=str(asset.get("cert_public_key_bits", 0))),
                Property(name="quantum-safe:pqc_status", value=asset.get("pqc_status", "")),
                Property(name="quantum-safe:risk_level", value=asset.get("risk_level", "")),
                Property(name="quantum-safe:is_quantum_safe", value=str(asset.get("is_quantum_safe", False))),
            ]

            comp = Component(
                name=f"TLS-{asset.get('host', 'unknown')}:{asset.get('port', 0)}",
                component_type=ComponentType.CRYPTOGRAPHIC_ASSET,
                version=asset.get("protocol_version", ""),
                description=(
                    f"Cryptographic asset on {asset.get('host')}:{asset.get('port')} "
                    f"— {asset.get('pqc_status', 'unknown')}"
                ),
                properties=props,
            )
            bom.components.add(comp)

        outputter = JsonV1Dot6(bom)
        return outputter.output_as_string()

    # ------------------------------------------------------------------
    # Manual fallback
    # ------------------------------------------------------------------

    def _generate_manual(self, cbom_dict: Dict[str, Any]) -> str:
        """Hand-craft a CycloneDX 1.6 JSON document."""
        components: List[Dict[str, Any]] = []

        for asset in cbom_dict.get("assets", []):
            comp = {
                "type": "cryptographic-asset",
                "bom-ref": asset.get("asset_id", str(uuid.uuid4())),
                "name": f"TLS-{asset.get('host', 'unknown')}:{asset.get('port', 0)}",
                "version": asset.get("protocol_version", ""),
                "description": (
                    f"Cryptographic asset on {asset.get('host')}:{asset.get('port')} "
                    f"— {asset.get('pqc_status', 'unknown')}"
                ),
                "properties": [
                    {"name": "quantum-safe:protocol", "value": asset.get("protocol_version", "")},
                    {"name": "quantum-safe:cipher_suite", "value": asset.get("cipher_suite", "")},
                    {"name": "quantum-safe:key_exchange", "value": asset.get("key_exchange", "")},
                    {"name": "quantum-safe:cipher_bits", "value": str(asset.get("cipher_bits", 0))},
                    {"name": "quantum-safe:cert_subject", "value": asset.get("cert_subject", "")},
                    {"name": "quantum-safe:cert_issuer", "value": asset.get("cert_issuer", "")},
                    {"name": "quantum-safe:cert_signature_algorithm", "value": asset.get("cert_signature_algorithm", "")},
                    {"name": "quantum-safe:cert_public_key_type", "value": asset.get("cert_public_key_type", "")},
                    {"name": "quantum-safe:cert_public_key_bits", "value": str(asset.get("cert_public_key_bits", 0))},
                    {"name": "quantum-safe:cert_fingerprint", "value": asset.get("cert_fingerprint", "")},
                    {"name": "quantum-safe:pqc_status", "value": asset.get("pqc_status", "")},
                    {"name": "quantum-safe:risk_level", "value": asset.get("risk_level", "")},
                    {"name": "quantum-safe:is_quantum_safe", "value": str(asset.get("is_quantum_safe", False))},
                ],
            }
            components.append(comp)

        doc = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": CBOM_SPEC_VERSION,
            "serialNumber": cbom_dict.get("serial_number", f"urn:uuid:{uuid.uuid4()}"),
            "version": cbom_dict.get("version", 1),
            "metadata": {
                "timestamp": cbom_dict.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": APP_NAME,
                            "version": APP_VERSION,
                        }
                    ]
                },
                "properties": [
                    {"name": "quantum-safe:total_assets", "value": str(cbom_dict.get("summary", {}).get("total_assets", 0))},
                    {"name": "quantum-safe:quantum_safe_count", "value": str(cbom_dict.get("summary", {}).get("quantum_safe", 0))},
                    {"name": "quantum-safe:quantum_vulnerable_count", "value": str(cbom_dict.get("summary", {}).get("quantum_vulnerable", 0))},
                ],
            },
            "components": components,
        }

        return json.dumps(doc, indent=2, ensure_ascii=False)
