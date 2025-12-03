from app.tx import Tx
from app.utils import canonical_json_bytes


def test_tx_to_dict_basic_fields():
    tx = Tx(
        from_addr="0xAAA",
        to_addr="0xBBB",
        value="100",
        nonce=42,
        gas_limit=21000,
        data_hex="deadbeef",
        timestamp="2025-01-01T00:00:00Z",
    )

    d = tx.to_dict()
    assert d["from"] == "0xAAA"
    assert d["to"] == "0xBBB"
    assert d["value"] == "100"
    # nonce se guarda como string
    assert d["nonce"] == "42"
    # timestamp respetado
    assert d["timestamp"] == "2025-01-01T00:00:00Z"
    # gas_limit y data_hex opcionales presentes como string
    assert d["gas_limit"] == "21000"
    assert d["data_hex"] == "deadbeef"


def test_tx_timestamp_autofilled():
    tx = Tx(
        from_addr="0xAAA",
        to_addr="0xBBB",
        value="1",
        nonce=1,
    )
    d = tx.to_dict()
    # Si no damos timestamp, debe agregarse uno
    assert "timestamp" in d
    assert isinstance(d["timestamp"], str)


def test_canonical_bytes_uses_canonical_json():
    tx = Tx(
        from_addr="0xAAA",
        to_addr="0xBBB",
        value="1",
        nonce=1,
        timestamp="2025-01-01T00:00:00Z",
    )
    d = tx.to_dict()
    canon_tx = tx.canonical_bytes()
    canon_manual = canonical_json_bytes(d)

    assert canon_tx == canon_manual
