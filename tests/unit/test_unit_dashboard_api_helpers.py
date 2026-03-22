from web.app import app
from web.routes.dashboard_api import _envelope, _parse_common_params


def test_parse_common_params_normalizes_values():
    with app.test_request_context("/api/assets?page=-2&page_size=999&order=DESC&sort=target&q=abc"):
        params = _parse_common_params()
    assert params["page"] == 1
    assert params["page_size"] == 250
    assert params["order"] == "desc"
    assert params["sort"] == "target"
    assert params["q"] == "abc"


def test_envelope_contains_required_shape():
    params = {"page": 1, "page_size": 10}
    body = _envelope(items=[{"id": 1}], total=1, params=params, kpis={"total_assets": 1})
    assert body["items"] == [{"id": 1}]
    assert body["total"] == 1
    assert body["page"] == 1
    assert body["page_size"] == 10
    assert body["total_pages"] == 1
    assert "kpis" in body
