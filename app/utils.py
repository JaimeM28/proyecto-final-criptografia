import json

# Implementacion básica de canonical json 
def canonical_json_bytes(obj) -> bytes:
    """
    Serializa un objeto a un JSON canónico (RFC 8785 subset).
    Ordena llaves, quita espacios y usa UTF-8.
    """
    return json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")