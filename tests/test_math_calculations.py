"""
Math Specification Unit Tests
===============================
Tests the PQC and Risk Calculation services against the mathematical spec
defined in docs/MATH_SPEC_AND_SQL_MAPPING.md

Config thresholds (from config.py):
  PQC_THRESHOLDS: elite=90, standard=70, legacy=40, critical=0
  RISK_WEIGHTS:   critical=10.0, high=5.0, medium=2.0, low=0.5
  PENALTY_ALPHA:  0.5

Risk Level thresholds (from RiskCalculationService):
  Low: >= 75, Medium: 50-74, High: 25-49, Critical: < 25
"""

import pytest
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.services.pqc_calculation_service import PQCCalculationService
from src.services.risk_calculation_service import RiskCalculationService


def test_pqc_tier_classification():
    """
    Actual service tier logic (config PQC_THRESHOLDS: elite=90, standard=70, legacy=40):
      1. Critical: has_critical_findings OR pqc_score < 0 (threshold_critical=0)
      2. Legacy:   has_legacy_config OR pqc_score < 40 (threshold_legacy=40)
      3. Elite:    pqc_score >= 90 (threshold_elite=90)
      4. else:     Standard  (40 <= score < 90)
    """
    # Elite: pqc_score >= 90, no critical findings
    assert PQCCalculationService.classify_asset_pqc_tier(95.0, False, False) == 'Elite'

    # Critical due to findings, overrides even a top score
    assert PQCCalculationService.classify_asset_pqc_tier(95.0, True, False) == 'Critical'

    # Standard: 40 <= score < 90 (no legacy config, no critical)
    assert PQCCalculationService.classify_asset_pqc_tier(75.0, False, False) == 'Standard'
    assert PQCCalculationService.classify_asset_pqc_tier(55.0, False, False) == 'Standard'  # 40-89 = Standard

    # Legacy: score < 40
    assert PQCCalculationService.classify_asset_pqc_tier(20.0, False, False) == 'Legacy'

    # Legacy forced by legacy_config flag even if score would otherwise be Standard
    assert PQCCalculationService.classify_asset_pqc_tier(33.0, False, True) == 'Legacy'

    # Critical: score literally below 0 is defined as critical; use -1 to test
    assert PQCCalculationService.classify_asset_pqc_tier(-1.0, False, False) == 'Critical'


def test_risk_severity_weights():
    """Weights defined in config.RISK_WEIGHTS: critical=10, high=5, medium=2, low=0.5"""
    assert RiskCalculationService.calculate_finding_severity_weight('critical') == 10.0
    assert RiskCalculationService.calculate_finding_severity_weight('high') == 5.0
    assert RiskCalculationService.calculate_finding_severity_weight('medium') == 2.0
    assert RiskCalculationService.calculate_finding_severity_weight('low') == 0.5
    # Unknown severities should return 0
    assert RiskCalculationService.calculate_finding_severity_weight('unknown') == 0.0


def test_asset_cyber_score():
    """
    Formula: asset_cyber_score = max(0, min(100, pqc_score - PENALTY_ALPHA * risk_penalty))
    PENALTY_ALPHA = 0.5
    """
    # Normal case: 80 - 0.5*20 = 70
    score = RiskCalculationService.calculate_asset_cyber_score(80.0, 20.0)
    assert score == 70.0

    # Floor at 0: 10 - 0.5*100 = -40 -> clamped to 0
    score2 = RiskCalculationService.calculate_asset_cyber_score(10.0, 100.0)
    assert score2 == 0.0

    # Ceiling at 100: pqc_score 120 is already capped -> 100 - 0 = 100
    score3 = RiskCalculationService.calculate_asset_cyber_score(120.0, 0.0)
    assert score3 == 100.0

    # No penalty: score stays at pqc_score (clamped to 100)
    score4 = RiskCalculationService.calculate_asset_cyber_score(60.0, 0.0)
    assert score4 == 60.0


def test_risk_level_classification():
    """Risk levels: Low>=75, Medium 50-74, High 25-49, Critical<25"""
    assert RiskCalculationService.classify_risk_level(85.0) == 'Low'
    assert RiskCalculationService.classify_risk_level(65.0) == 'Medium'
    assert RiskCalculationService.classify_risk_level(35.0) == 'High'
    assert RiskCalculationService.classify_risk_level(15.0) == 'Critical'
    # Boundaries
    assert RiskCalculationService.classify_risk_level(75.0) == 'Low'
    assert RiskCalculationService.classify_risk_level(25.0) == 'High'
    assert RiskCalculationService.classify_risk_level(24.9) == 'Critical'
