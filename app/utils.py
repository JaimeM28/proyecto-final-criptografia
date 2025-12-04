import json

# Implementacion básica de canonical json 
def canonical_json_bytes(obj) -> bytes:
    """
    Serializa un objeto Python a JSON canónico (subconjunto de RFC 8785).

    Args:
        obj (Any): Objeto serializable a JSON (dict, list, str, int, etc.).

    Returns:
        bytes: Representación JSON canónica codificada en UTF-8.

    Raises:
        TypeError: Si el objeto no es serializable a JSON.
        ValueError: Si ocurre un error durante la serialización.
    """
    return json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")