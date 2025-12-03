import base64

from nacl.signing import SigningKey

from app.address import keccak256, address_from_pubkey, load_address_from_keystore
from app.keystore import DEFAULT_KEYSTORE_PATH


def test_keccak256_returns_32_bytes():
    data = b"hola mundo"
    digest = keccak256(data)
    assert isinstance(digest, bytes)
    assert len(digest) == 32  # 256 bits


def test_address_from_pubkey_format():
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()

    addr = address_from_pubkey(pub)
    # Debe empezar con 0x y tener 40 hex chars (20 bytes)
    assert addr.startswith("0x")
    assert len(addr) == 2 + 40


def test_load_address_from_keystore(tmp_path, monkeypatch):
    """
    Creamos un keystore falso mínimo con pubkey_b64 y probamos
    que load_address_from_keystore lo lea correctamente.
    """
    ks_path = tmp_path / "keystore.json"

    # Generamos una pubkey cualquiera
    sk = SigningKey.generate()
    pub_bytes = sk.verify_key.encode()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    fake_doc = {
        "scheme": "Ed25519",
        "pubkey_b64": pub_b64,
    }
    ks_path.write_text(
        # Nota: el loader de address solo lee scheme y pubkey_b64
        __import__("json").dumps(fake_doc),
        encoding="utf-8",
    )

    scheme, pubkey_b64, address = load_address_from_keystore(ks_path)

    assert scheme == "Ed25519"
    assert pubkey_b64 == pub_b64
    assert address.startswith("0x")
    assert len(address) == 42
