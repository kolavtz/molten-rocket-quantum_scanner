import sys, os
sys.path.insert(0, ".")
from src.services.pqc_calculation_service import PQCCalculationService
from src.services.risk_calculation_service import RiskCalculationService

def run_test(name, fn):
    try:
        fn()
        print(f"PASS: {name}")
    except AssertionError as e:
        print(f"FAIL: {name}: {e}")
    except Exception as e:
        print(f"ERROR: {name}: {type(e).__name__}: {e}")

# test_pqc_tier_classification
def test_pqc():
    assert PQCCalculationService.classify_asset_pqc_tier(95.0, False, False) == 'Elite', f"Got: {PQCCalculationService.classify_asset_pqc_tier(95.0, False, False)}"
    assert PQCCalculationService.classify_asset_pqc_tier(95.0, True, False) == 'Critical', f"Got: {PQCCalculationService.classify_asset_pqc_tier(95.0, True, False)}"
    assert PQCCalculationService.classify_asset_pqc_tier(75.0, False, False) == 'Standard', f"Got: {PQCCalculationService.classify_asset_pqc_tier(75.0, False, False)}"
    assert PQCCalculationService.classify_asset_pqc_tier(55.0, False, False) == 'Legacy', f"Got: {PQCCalculationService.classify_asset_pqc_tier(55.0, False, False)}"
    assert PQCCalculationService.classify_asset_pqc_tier(20.0, False, False) == 'Critical', f"Got: {PQCCalculationService.classify_asset_pqc_tier(20.0, False, False)}"
    assert PQCCalculationService.classify_asset_pqc_tier(33.0, False, True) == 'Legacy', f"Got: {PQCCalculationService.classify_asset_pqc_tier(33.0, False, True)}"

def test_weights():
    assert RiskCalculationService.calculate_finding_severity_weight('critical') == 10.0
    assert RiskCalculationService.calculate_finding_severity_weight('high') == 5.0
    assert RiskCalculationService.calculate_finding_severity_weight('medium') == 2.0
    assert RiskCalculationService.calculate_finding_severity_weight('low') == 0.5
    assert RiskCalculationService.calculate_finding_severity_weight('unknown') == 0.0

def test_cyber_score():
    score = RiskCalculationService.calculate_asset_cyber_score(80.0, 20.0)
    assert score == 70.0, f"Expected 70.0, got {score}"
    score2 = RiskCalculationService.calculate_asset_cyber_score(10.0, 100.0)
    assert score2 == 0.0, f"Expected 0.0, got {score2}"
    score3 = RiskCalculationService.calculate_asset_cyber_score(120.0, 0.0)
    assert score3 == 100.0, f"Expected 100.0, got {score3}"
    score4 = RiskCalculationService.calculate_asset_cyber_score(60.0, 0.0)
    assert score4 == 60.0, f"Expected 60.0, got {score4}"

def test_risk_level():
    assert RiskCalculationService.classify_risk_level(85.0) == 'Low', f"Got: {RiskCalculationService.classify_risk_level(85.0)}"
    assert RiskCalculationService.classify_risk_level(65.0) == 'Medium', f"Got: {RiskCalculationService.classify_risk_level(65.0)}"
    assert RiskCalculationService.classify_risk_level(35.0) == 'High', f"Got: {RiskCalculationService.classify_risk_level(35.0)}"
    assert RiskCalculationService.classify_risk_level(15.0) == 'Critical', f"Got: {RiskCalculationService.classify_risk_level(15.0)}"
    assert RiskCalculationService.classify_risk_level(75.0) == 'Low', f"Got: {RiskCalculationService.classify_risk_level(75.0)}"
    assert RiskCalculationService.classify_risk_level(25.0) == 'High', f"Got: {RiskCalculationService.classify_risk_level(25.0)}"
    assert RiskCalculationService.classify_risk_level(24.9) == 'Critical', f"Got: {RiskCalculationService.classify_risk_level(24.9)}"

run_test("test_pqc_tier_classification", test_pqc)
run_test("test_risk_severity_weights", test_weights)
run_test("test_asset_cyber_score", test_cyber_score)
run_test("test_risk_level_classification", test_risk_level)
