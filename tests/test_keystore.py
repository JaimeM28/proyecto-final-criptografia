import json
import base64

import pytest
from nacl.signing import VerifyKey

from app.keystore import (
    create,
    load,
    kdf_argon2id,
    aesgcm_encrypt,
    DEFAULT_KEYSTORE_PATH,
)


def test_kdf_argon2id_invalid_salt_raises():
    # Salt muy corta debe disparar ValueError
    with pytest.raises(ValueError):
        kdf_argon2id("pass", b"short")


def test_aesgcm_encrypt_invalid_key_len_raises():
    from app.keystore import aesgcm_encrypt
    with pytest.raises(ValueError):
        aesgcm_encrypt(b"too_short_key", b"hola")


def test_create_and_load_roundtrip(tmp_path):
    """
    create() genera un keystore válido y load() lo descifra correctamente.
    """
    ks_path = tmp_path / "keystore.json"

    # Crear keystore
    doc = create("mi-pass", ks_path)
    assert ks_path.exists()
    assert doc["scheme"] == "Ed25519"
    assert "pubkey_b64" in doc

    # Cargar keystore
    state = load("mi-pass", ks_path)
    sk = state["sk"]
    vk = state["vk"]
    pubkey_bytes = state["pubkey_bytes"]

    # La pubkey que devuelve load debe coincidir con la guardada en el JSON
    stored_pub_b64 = doc["pubkey_b64"]
    stored_pub_bytes = base64.b64decode(stored_pub_b64.encode("ascii"))

    assert pubkey_bytes == stored_pub_bytes
    assert isinstance(vk, VerifyKey)
    # La verify_key de la llave privada debe coincidir con pubkey_bytes
    assert vk.encode() == pubkey_bytes


def test_load_detects_checksum_tampering(tmp_path):
    """
    Si alguien modifica el keystore en disco, load() debe fallar por checksum inválido.
    """
    ks_path = tmp_path / "keystore.json"
    create("secret", ks_path)

    # Cargar JSON y alterar un campo
    data = json.loads(ks_path.read_text(encoding="utf-8"))
    data["scheme"] = "AlgoRaro"
    ks_path.write_text(json.dumps(data), encoding="utf-8")

    from app.keystore import load as load_ks

    with pytest.raises(ValueError) as excinfo:
        load_ks("secret", ks_path)

    assert "Checksum inválido" in str(excinfo.value)
