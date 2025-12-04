# tests/test_verifier.py
import json
import base64
from pathlib import Path

from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError

import pytest

from app.verifier import (
    verify_tx,
    commit_verification,
    NONCE_TRACKER_PATH,
)
from app.utils import canonical_json_bytes
from app.address import address_from_pubkey


@pytest.fixture(autouse=True)
def use_temp_nonce_tracker(tmp_path, monkeypatch):
    """
    Antes de cada prueba:
    - Redirige NONCE_TRACKER_PATH a un archivo temporal.
    - Así no modificamos app/nonce_tracker.json real.
    """
    fake_tracker = tmp_path / "nonce_tracker.json"
    monkeypatch.setattr("app.verifier.NONCE_TRACKER_PATH", fake_tracker)
    yield


def make_signed_tx(sk: SigningKey, from_addr: str, to: str, nonce: int):
    tx = {
        "from": from_addr,
        "to": to,
        "value": "10",
        "nonce": str(nonce),
        "timestamp": "2025-01-01T00:00:00Z",
    }
    msg = canonical_json_bytes(tx)

    signed = sk.sign(msg)
    signature_b64 = base64.b64encode(signed.signature).decode("ascii")
    pubkey_b64 = base64.b64encode(sk.verify_key.encode()).decode("ascii")

    return {
        "tx": tx,
        "signature_b64": signature_b64,
        "pubkey_b64": pubkey_b64,
        "sig_scheme": "Ed25519",
    }


def test_verify_valid_transaction():
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()
    addr = address_from_pubkey(pub)

    signed_tx = make_signed_tx(sk, addr, "0xBBBB", 1)

    ok, reason = verify_tx(signed_tx)
    assert ok is True
    assert reason is None


def test_verify_invalid_signature():
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()
    addr = address_from_pubkey(pub)

    signed_tx = make_signed_tx(sk, addr, "0xBBBB", 1)

    # Romper la firma cambiando un byte
    broken_sig = base64.b64decode(signed_tx["signature_b64"])
    broken_sig = bytearray(broken_sig)
    broken_sig[0] ^= 0xFF  # flip first byte
    signed_tx["signature_b64"] = base64.b64encode(bytes(broken_sig)).decode("ascii")

    ok, reason = verify_tx(signed_tx)
    assert ok is False
    assert "Firma digital inválida" in reason


def test_verify_wrong_address():
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()
    real_addr = address_from_pubkey(pub)

    signed_tx = make_signed_tx(sk, real_addr, "0xBBBB", 1)

    # Cambiar el campo from por una address falsa
    signed_tx["tx"]["from"] = "0x1234567890000000000000000000000000000000"

    ok, reason = verify_tx(signed_tx)
    assert ok is False
    assert "Dirección no coincide" in reason


def test_verify_nonce_ok(tmp_path, monkeypatch):
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()
    addr = address_from_pubkey(pub)

    # Redirigir tracker a archivo temporal
    tracker_path = tmp_path / "nonce_tracker.json"
    monkeypatch.setattr("app.verifier.NONCE_TRACKER_PATH", tracker_path)

    signed_tx = make_signed_tx(sk, addr, "0xBBBB", 1)

    ok, reason = verify_tx(signed_tx)
    assert ok is True


def test_verify_replay_nonce_fails(tmp_path, monkeypatch):
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()
    addr = address_from_pubkey(pub)

    tracker_path = tmp_path / "nonce_tracker.json"
    monkeypatch.setattr("app.verifier.NONCE_TRACKER_PATH", tracker_path)

    # Guardamos que ya vimos nonce 5
    tracker_path.write_text(json.dumps({addr: 5}))

    # Intento usar nonce 3 → replay
    signed_tx = make_signed_tx(sk, addr, "0xBBBB", 3)

    ok, reason = verify_tx(signed_tx)
    assert ok is False
    assert "Nonce inválido o repetido" in reason


def test_commit_verification_updates_tracker(tmp_path, monkeypatch):
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()
    addr = address_from_pubkey(pub)

    # Redirigir tracker
    tracker_path = tmp_path / "nonce_tracker.json"
    monkeypatch.setattr("app.verifier.NONCE_TRACKER_PATH", tracker_path)

    signed_tx = make_signed_tx(sk, addr, "0xBBBB", 10)

    # commit
    commit_verification(signed_tx)

    data = json.loads(tracker_path.read_text())
    assert data[addr] == 10
