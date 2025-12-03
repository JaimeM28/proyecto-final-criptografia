import base64

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from app.signer import sign
from app.utils import canonical_json_bytes


def test_sign_returns_expected_fields():
    sk = SigningKey.generate()
    tx = {
        "from": "0xAAA",
        "to": "0xBBB",
        "value": "10",
        "nonce": "1",
        "timestamp": "2025-01-01T00:00:00Z",
    }

    signed = sign(sk, tx)

    assert "tx" in signed
    assert "sig_scheme" in signed
    assert "signature_b64" in signed
    assert "pubkey_b64" in signed

    assert signed["sig_scheme"] == "Ed25519"
    # La tx que regresa debe ser canónica (ordenada)
    canon = canonical_json_bytes(tx).decode("utf-8")
    assert signed["tx"] == __import__("json").loads(canon)


def test_sign_signature_verifies():
    """
    Verificamos criptográficamente que la firma devuelta es válida
    para el mensaje canónico tx.
    """
    sk = SigningKey.generate()
    tx = {
        "from": "0xAAA",
        "to": "0xBBB",
        "value": "10",
        "nonce": "1",
        "timestamp": "2025-01-01T00:00:00Z",
    }

    signed = sign(sk, tx)

    pubkey_bytes = base64.b64decode(signed["pubkey_b64"].encode("ascii"))
    sig_bytes = base64.b64decode(signed["signature_b64"].encode("ascii"))

    vk = VerifyKey(pubkey_bytes)
    msg = canonical_json_bytes(signed["tx"])

    # No debe lanzar BadSignatureError si la firma es correcta
    vk.verify(msg, sig_bytes)

    # Y si alteramos el mensaje, debe fallar
    tampered_msg = canonical_json_bytes({**signed["tx"], "value": "999"})
    try:
        vk.verify(tampered_msg, sig_bytes)
        # Si no lanza, algo anda mal
        assert False, "La verificación debería fallar con mensaje alterado"
    except BadSignatureError:
        pass
