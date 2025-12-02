# app/address.py

import json
import base64
from pathlib import Path
from Crypto.Hash import keccak
from .keystore import DEFAULT_KEYSTORE_PATH


def keccak256(data: bytes) -> bytes:
    """ Aquí se alcula KECCAK-256(data) , esta sugerencia es la del docuemento en el proyecto devolviendo 32 bytes.
    """
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def address_from_pubkey(pubkey_bytes: bytes) -> str:
    """ En esta parte deriva la dirección desde la clave pública.
    Especificación: KECCAK-256(pubkey)[12..31], aquí debido a que los últimos 20 bytes del hash (20 bytes = 40 hex)
    """
    digest = keccak256(pubkey_bytes)
    addr_bytes = digest[-20:]  # bytes 12..31
    return "0x" + addr_bytes.hex()


def load_address_from_keystore(path: Path | None = None) -> tuple[str, str, str]:
    """
    Aquí lee keystore.json, extrae pubkey_b64 y deriva el scheme, pubkey_b64 y address_hex
    """
    ks_path = path or DEFAULT_KEYSTORE_PATH
    data = json.loads(ks_path.read_text(encoding="utf-8"))

    scheme = data.get("scheme", "Ed25519")
    pubkey_b64 = data["pubkey_b64"]
    pubkey = base64.b64decode(pubkey_b64)

    address = address_from_pubkey(pubkey)
    return scheme, pubkey_b64, address