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
from .utils import canonical_json_bytes 
from typing import Optional
from nacl.signing import VerifyKey 

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

def b64d(s: str) -> bytes:
    """Decodifica Base64 (string -> bytes)."""
    return base64.b64decode(s.encode("ascii"))

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, *, aad: Optional[bytes] = None) -> bytes:
    """Operacion inversa de aesgcm_encrypt."""
    if len(key) != 32:
        raise ValueError("AESGCM requiere llave de 32 bytes (256-bit)")
    aes = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aes.decrypt(nonce, ct_with_tag, aad)

def kdf_argon2id_from_params(passphrase: str, kdf_params: dict) -> bytes:
    """Re-deriva la clave simétrica a partir de los parámetros guardados en el keystore."""
    salt = b64d(kdf_params["salt_b64"])
    return kdf_argon2id(
        passphrase,
        salt,
        t_cost=int(kdf_params["t_cost"]),
        m_cost=int(kdf_params["m_cost"]),
        parallelism=int(kdf_params["p"]),
    )

def load(passphrase: str, path: Path = DEFAULT_KEYSTORE_PATH) -> dict:
    """
    Carga y descifra el keystore:
    - Verifica checksum
    - Deriva la clave simétrica con Argon2id
    - Descifra la private key Ed25519

    Devuelve:
    {
      "sk": SigningKey,
      "vk": VerifyKey,
      "pubkey_bytes": bytes,
      "doc": dict del keystore
    }
    """
    with path.open("r", encoding="utf-8") as f:
        full_doc = json.load(f)

    # 1) Verificar checksum
    expected = full_doc.get("checksum")
    doc_sin_checksum = dict(full_doc)
    doc_sin_checksum.pop("checksum", None)
    real = _keystore_checksum(doc_sin_checksum)
    if real != expected:
        raise ValueError("Checksum inválido: el keystore fue modificado o está corrupto.")

    # 2) Verificar KDF
    if full_doc.get("kdf") != "Argon2id":
        raise ValueError("KDF no soportado (se esperaba Argon2id).")

    # 3) Derivar clave simétrica
    kdf_params = full_doc["kdf_params"]
    key = kdf_argon2id_from_params(passphrase, kdf_params)

    # 4) Descifrar private key
    nonce = b64d(full_doc["cipher_params"]["nonce_b64"])
    ciphertext = b64d(full_doc["ciphertext_b64"])
    tag = b64d(full_doc["tag_b64"])
    sk_bytes = aesgcm_decrypt(key, nonce, ciphertext, tag)

    sk = SigningKey(sk_bytes)
    vk: VerifyKey = sk.verify_key
    pubkey_bytes = vk.encode()

    return {
        "sk": sk,
        "vk": vk,
        "pubkey_bytes": pubkey_bytes,
        "doc": full_doc,
    }