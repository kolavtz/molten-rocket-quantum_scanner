from src.services.pqc_service import PQCService


def test_score_to_pqc_tier_boundaries():
    assert PQCService._score_to_pqc_tier(90) == "Elite"
    assert PQCService._score_to_pqc_tier(65) == "Standard"
    assert PQCService._score_to_pqc_tier(45) == "Legacy"
    assert PQCService._score_to_pqc_tier(10) == "Critical"


def test_build_recommendations_empty_assets():
    recs = PQCService._build_recommendations(0, 0, 0, 0, 0, 0)
    assert recs == ["No active assets to assess."]


def test_build_empty_response_shape():
    payload = PQCService._build_empty_response()
    assert "kpis" in payload
    assert "applications" in payload
    assert payload["meta"]["total_assets"] == 0
