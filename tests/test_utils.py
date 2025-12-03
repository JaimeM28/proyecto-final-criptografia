from app.utils import canonical_json_bytes


def test_canonical_json_sorts_keys_and_removes_spaces():
    data = {"b": 2, "a": 1}
    result = canonical_json_bytes(data).decode("utf-8")

    # Llaves ordenadas y sin espacios
    assert result == '{"a":1,"b":2}'
