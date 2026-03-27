from src.services.digital_label_service import DigitalLabelService


def test_assign_label_at_risk_due_to_critical_findings():
    label, reason = DigitalLabelService.assign_label(
        pqc_score=95,
        total_findings=1,
        critical_findings=1,
        enterprise_score=900,
    )
    assert label == "At Risk"
    assert "critical findings" in str(reason.get("reason", "")).lower()


def test_assign_label_fully_quantum_safe():
    label, reason = DigitalLabelService.assign_label(
        pqc_score=96,
        total_findings=0,
        critical_findings=0,
        enterprise_score=760,
    )
    assert label == "Fully Quantum Safe"
    assert "min_enterprise_score" in reason.get("thresholds", {})


def test_assign_label_quantum_safe_when_enterprise_below_full_threshold():
    label, _ = DigitalLabelService.assign_label(
        pqc_score=93,
        total_findings=1,
        critical_findings=0,
        enterprise_score=650,
    )
    assert label == "Quantum-Safe"


def test_assign_label_pqc_ready_band():
    label, _ = DigitalLabelService.assign_label(
        pqc_score=78,
        total_findings=2,
        critical_findings=0,
        enterprise_score=500,
    )
    assert label == "PQC Ready"


def test_confidence_score_penalizes_findings_and_critical():
    high_conf = DigitalLabelService.calculate_confidence_score(
        label="Quantum-Safe",
        pqc_score=95,
        total_findings=0,
        critical_findings=0,
    )
    lower_conf = DigitalLabelService.calculate_confidence_score(
        label="Quantum-Safe",
        pqc_score=95,
        total_findings=5,
        critical_findings=1,
    )
    assert high_conf > lower_conf
    assert 0 <= lower_conf <= 100
    assert 0 <= high_conf <= 100
