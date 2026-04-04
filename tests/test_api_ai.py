import json
from unittest.mock import patch
import pytest

from web.app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["LOGIN_DISABLED"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as c:
        yield c


@patch("src.services.ai.llm_client.LLMClient.generate")
@patch("src.services.ai.retriever.build_cbom_context")
def test_cbom_query_endpoint(mock_retriever, mock_generate, client):
    mock_retriever.return_value = {"text": "KPIs: total_applications: 0", "kpis": {}, "samples": []}
    mock_generate.return_value = "Sample assistant reply."

    resp = client.post("/api/ai/cbom-query", json={"query": "What are weak keys?"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "answer" in data
    assert "Sample assistant reply." in data["answer"]
