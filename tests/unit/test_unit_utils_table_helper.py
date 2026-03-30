from utils.table_helper import paginate_query


def test_paginate_sequence_sorts_and_filters():
    rows = [
        {"name": "gamma", "owner": "team-a"},
        {"name": "alpha", "owner": "team-b"},
        {"name": "beta", "owner": "team-c"},
    ]
    result = paginate_query(
        rows,
        page=1,
        page_size=25,
        sort="name",
        order="asc",
        search="a",
        searchable_columns=["name"],
    )
    names = [row["name"] for row in result["items"]]
    assert names == ["alpha", "beta", "gamma"]
    assert result["total_count"] == 3


def test_paginate_sequence_page_size_normalization():
    rows = [{"name": f"item-{i}"} for i in range(30)]
    result = paginate_query(rows, page=1, page_size=7, sort="name", order="asc")
    assert result["page_size"] == 10
    assert result["total_pages"] == 3
