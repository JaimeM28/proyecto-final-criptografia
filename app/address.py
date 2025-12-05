# app/address.py

import json
import base64
from pathlib import Path
from Crypto.Hash import keccak
from .keystore import DEFAULT_KEYSTORE_PATH


def keccak256(data: bytes) -> bytes:
    """
    En esta función se calcula el hash KECCAK-256 de los datos proporcionados, decidimos tomar esta sugerencia la tomamos por parte de la recomendación del documento del proyecto.

    Args:
        data (bytes): Son los datos de entrada a hashear.

    Returns:
        bytes: Hash KECCAK-256 de 32 bytes.

    Raises:
        TypeError: Si el "data" no es de tipo bytes.
    """
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def address_from_pubkey(pubkey_bytes: bytes) -> str:
    """
    Aquí se deriva la dirección hexadecimal a partir de una clave pública.
    El procedimiento sigue la especificación Ethereum‑like: dirección = KECCAK‑256(pubkey)[‑20:] donde vemos que toma los últimos 20 bytes del hash.

    Args:
        pubkey_bytes (bytes): Es la clave pública en bytes (normalmente 32 bytes para Ed25519).

    Returns:
        str: Dirección derivada en formato hexadecimal con prefijo "0x".

    Raises:
        TypeError: Si "pubkey_bytes" no es bytes.
        ValueError: Si la clave pública no tiene una longitud válida.
    """
    digest = keccak256(pubkey_bytes)
    addr_bytes = digest[-20:]  # bytes 12..31
    return "0x" + addr_bytes.hex()


def load_address_from_keystore(path: Path | None = None) -> tuple[str, str, str]:
    """
    En esta funcion se lee un archivo de keystore y deriva la dirección contenida.
    El keystore debe contener al menos el campo "pubkey_b64". Se decodifica la clave pública, se deriva la dirección y se regresan los valores.

    Args:
        path (Path | None): Ruta del archivo keystore.json. Si es None se usa DEFAULT_KEYSTORE_PATH.

    Returns:
        tuple[str, str, str]: (scheme, pubkey_b64, address_hex)

    Raises:
        FileNotFoundError: Si el archivo de keystore no existe.
        KeyError: Si faltan campos obligatorios como "pubkey_b64".
        json.JSONDecodeError: Si es que el archivo contiene JSON inválido.
    """
    ks_path = path or DEFAULT_KEYSTORE_PATH
    data = json.loads(ks_path.read_text(encoding="utf-8"))

    scheme = data.get("scheme", "Ed25519")
    pubkey_b64 = data["pubkey_b64"]
    pubkey = base64.b64decode(pubkey_b64)

    address = address_from_pubkey(pubkey)
    return scheme, pubkey_b64, address