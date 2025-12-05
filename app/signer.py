import json
from typing import Dict, Any

from nacl.signing import SigningKey
from .utils import canonical_json_bytes
from .keystore import b64e


def sign(private_key: SigningKey, tx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Signer.sign(private_key, tx) -> SignedTx

    tx: dict con la transacción (from, to, value, nonce, etc.)
    Devuelve paquete firmado listo para guardar en outbox/.

    Args: private_key (SigningKey): Clave privada Ed25519 para firmar la transacción.
            tx (Dict[str, Any]): Diccionario que representa la transacción a firmar.

    returns: Dict[str, Any]: Diccionario que representa la transacción firmada, incluyendo la firma y la clave pública en base64.

    Raises: typeError: Si tx no es un diccionario.
            nacl.exceptions.CryptoError: Si la firma falla por alguna razón.



    """
    # 1) JSON canónico
    msg = canonical_json_bytes(tx)

    # 2) Firmar con Ed25519
    signed = private_key.sign(msg)
    signature = signed.signature  # 64 bytes

    pubkey_b64 = b64e(private_key.verify_key.encode())
    signature_b64 = b64e(signature)

    signed_tx = {
        "tx": json.loads(msg.decode("utf-8")),  # forma canónica
        "sig_scheme": "Ed25519",
        "signature_b64": signature_b64,
        "pubkey_b64": pubkey_b64,
    }
    return signed_tx
