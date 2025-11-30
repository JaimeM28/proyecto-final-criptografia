import json
import os
import base64
from pathlib import Path
from nacl.signing import SigningKey
from argon2.low_level import hash_secret_raw, Type
import hashlib
from datetime import datetime, timezone
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ruta por defecto donde se almacenará el keystore si no se indica otra.
DEFAULT_KEYSTORE_PATH = Path("app/keystore.json")

def kdf_argon2id(
    passphrase: str,
    salt: bytes,
    *,
    t_cost: int = 3,          # iteraciones
    m_cost: int = 64 * 1024,  # memoria en KiB (64 MiB)
    parallelism: int = 1,
    key_len: int = 32,        # 256-bit key
) -> bytes:
    """
    Deriva una clave simétrica a partir de una passphrase usando Argon2id.

    La función aplica Argon2id sobre la passphrase y una sal aleatoria
    para obtener una clave de longitud fija-

    :param passphrase: Passphrase en texto claro introducida por el usuario.
    :param salt: Sal aleatoria usada en el KDF (mínimo 16 bytes).
    :param t_cost: Número de iteraciones de Argon2id (parámetro de tiempo).
    :param m_cost: Memoria en KiB utilizada por Argon2id.
    :param parallelism: Grado de paralelismo (número de lanes).
    :param key_len: Longitud de la clave derivada en bytes.
    :return: Clave derivada como bytes.
    :raises ValueError: Si la sal es demasiado corta o de tipo inválido.
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("Salt inválida (min 16 bytes)")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=parallelism,
        hash_len=key_len,
        type=Type.ID,
    )

def b64e(b: bytes) -> str:
    """
    Codifica datos binarios en Base64 y devuelve una cadena ASCII.

    :param b: Datos binarios a codificar.
    :return: Cadena Base64 en ASCII.
    """
    return base64.b64encode(b).decode("ascii")

def aesgcm_encrypt(key: bytes, plaintext: bytes, *, aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Cifra datos con AES-256-GCM y separa nonce, ciphertext y tag.

    :param key: Clave simétrica de 32 bytes (AES-256).
    :param plaintext: Datos en claro a cifrar.
    :param aad: Datos adicionales autenticados (no cifrados), o None.
    :return: Tupla (nonce, ciphertext, tag).
    :raises ValueError: Si la longitud de la clave no es de 32 bytes.
    """
    if len(key) != 32:
        raise ValueError("AESGCM requiere llave de 32 bytes (256-bit)")
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct_with_tag = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct_with_tag[:-16], ct_with_tag[-16:]


# Implementacion básica de canonical json 
# TODO: definir canonical json basado en RFC 8785 
def canonical_json_bytes(obj) -> bytes:
    """
    Serializa un objeto a un JSON canónico
    :param obj: Objeto serializable a JSON.
    :return: Representación JSON canónica en bytes UTF-8.
    """
    return json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")


def _keystore_checksum(doc: dict) -> str:
    """
    Calcula el checksum de integridad de un JSON canonico.

    El checksum se define como el hash SHA-256 del JSON canónico sin el campo ``checksum``.

    :param doc: Archivo que contiene el json canonico sin el campo ``checksum``.
    :return: Hash SHA-256 en hexadecimal (64 caracteres).
    """
    return hashlib.sha256(canonical_json_bytes(doc)).hexdigest()

def create(passphrase: str, path: Path = DEFAULT_KEYSTORE_PATH) -> dict:
    """
    Genera un par Ed25519, cifra la clave privada con AES-256-GCM bajo
    una llave derivada con Argon2id y genera un archivo llamado keystore.json 
    para almacenar las claves e información.

    :param passphrase: Passphrase usada para derivar la llave simétrica.
    :param path: Ruta donde se guardará el archivo json.
    :return: Documento JSON (dict) que se guardó en disco.
    """

    # Generacion de claves Ed25519
    sk = SigningKey.generate()
    pk_bytes = sk.verify_key.encode()
    sk_bytes = sk.encode()
    
    # Derivacion de clave simétrica desde passphrase (Argon2id)
    salt = os.urandom(32)
    kdf_params = {"salt_b64": b64e(salt), "t_cost": 3, "m_cost": 64 * 1024, "p": 1}
    key = kdf_argon2id(passphrase, salt, t_cost=kdf_params["t_cost"], m_cost=kdf_params["m_cost"], parallelism=kdf_params["p"])

    # Cifrar clave privada con AES-256-GCM
    nonce, ct, tag = aesgcm_encrypt(key, sk_bytes)
    cipher_params = {"nonce_b64": b64e(nonce)}

    # Construir documento sin checksum
    doc = {
        "kdf": "Argon2id",
        "kdf_params": kdf_params,
        "cipher": "AES-256-GCM",
        "cipher_params": cipher_params,
        "ciphertext_b64": b64e(ct),
        "tag_b64": b64e(tag),
        "pubkey_b64": b64e(pk_bytes),
        "scheme": "Ed25519",
        "created": datetime.now(timezone.utc).isoformat(),
    }

    # Añadir checksum
    checksum = _keystore_checksum(doc)
    doc["checksum"] = checksum

    # 5) Guardar en disco
    with path.open("w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)

    return doc