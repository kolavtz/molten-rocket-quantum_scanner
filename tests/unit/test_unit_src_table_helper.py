from src.table_helper import paginate_query


class _FakeCol:
    def __init__(self, name):
        self.name = name

    def ilike(self, _pattern):
        return True


class _FakeModel:
    id = _FakeCol("id")
    name = _FakeCol("name")


class _FakeSortable:
    def __init__(self, name):
        self.name = name


class _FakeQuery:
    def __init__(self, rows):
        self.rows = list(rows)
        self._offset = 0
        self._limit = len(rows)

    def filter(self, *_args, **_kwargs):
        return self

    def count(self):
        return len(self.rows)

    def order_by(self, _expr):
        return self

    def offset(self, value):
        self._offset = int(value)
        return self

    def limit(self, value):
        self._limit = int(value)
        return self

    def all(self):
        return self.rows[self._offset : self._offset + self._limit]


def test_src_paginate_query_basic_shape(monkeypatch):
    monkeypatch.setattr("src.table_helper.desc", lambda col: _FakeSortable(f"desc:{col.name}"))
    monkeypatch.setattr("src.table_helper.asc", lambda col: _FakeSortable(f"asc:{col.name}"))

    query = _FakeQuery([{"id": 1}, {"id": 2}, {"id": 3}])
    result = paginate_query(
        query=query,
        model=_FakeModel,
        page=1,
        page_size=2,
        sort_field="id",
        sort_dir="asc",
        search_term="",
        searchable_columns=[],
    )

    assert result["total_count"] == 3
    assert result["page_size"] == 2
    assert result["total_pages"] == 2
    assert len(result["items"]) == 2
