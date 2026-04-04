import os
import pytest

from src.services.ai import rag


@pytest.mark.skipif(os.environ.get("QSS_RUN_RAG_TESTS") != "1", reason="RAG tests disabled by default")
def test_rag_reindex_and_search(tmp_path):
    # Use a temporary DB path so test doesn't interfere with local data
    db_path = str(tmp_path / "test_rag.db")
    os.environ["QSS_RAG_DB_PATH"] = db_path
    # Attempt a reindex (requires database access and CBOM data)
    count = rag.reindex_from_cbom(limit=100)
    assert isinstance(count, int)

    # If count is zero, that's still acceptable but search should not crash
    results = rag.search("certificate", limit=3)
    assert isinstance(results, list)
