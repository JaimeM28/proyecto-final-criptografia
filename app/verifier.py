import json
import base64
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from .utils import canonical_json_bytes
from .address import address_from_pubkey

# Archivo local para rastrear el último nonce visto de cada dirección
NONCE_TRACKER_PATH = Path("app/nonce_tracker.json")

def _load_nonce_tracker() -> Dict[str, int]:
    """
    Carga desde disco el rastreador de nonces por dirección.
    Si el archivo no existe o está corrupto, devuelve un diccionario vacío, para evitar que el verificador falle por errores de formato.

    Returns:
        Dict[str, int]: Mapeo de dirección (str) a último nonce visto (int).
    """
    if not NONCE_TRACKER_PATH.exists():
        return {}
    try:
        with NONCE_TRACKER_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def _save_nonce_tracker(data: Dict[str, int]) -> None:
    """
    Guarda en disco el rastreador de nonces por dirección.

    Args:
        data (Dict[str, int]): Mapeo de dirección (str) a último nonce visto (int).

    Returns:
        None

    Raises:
        OSError: Si ocurre un error al escribir el archivo en disco.
    """
    with NONCE_TRACKER_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def verify_tx(signed_tx: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Verifica criptográficamente una transacción firmada y valida contra ataques de replay.

    Args:
        signed_tx (Dict[str, Any]) : Paquete de transacción firmada:   
            - "tx": Dict con los campos de la transacción (incluyendo "from" y "nonce").
            - "signature_b64": Firma digital en Base64.
            - "pubkey_b64": Clave pública en Base64.
            - "sig_scheme": Esquema de firma (debe ser "Ed25519").

    Returns:
        Tuple[bool, Optional[str]]: Una tupla donde el primer elemento es True si la verificación fue exitosa, o False si falló.

    Raises:
        No lanza excepciones hacia afuera: cualquier error interno se captura
        y se reporta como (False, "mensaje de error").
    """
    
    # 1. Validación de Estructura
    required_fields = ["tx", "signature_b64", "pubkey_b64", "sig_scheme"]
    if not all(field in signed_tx for field in required_fields):
        return False, "Estructura JSON incompleta"

    tx_data = signed_tx["tx"]
    scheme = signed_tx["sig_scheme"]
    
    if scheme != "Ed25519":
        return False, f"Esquema de firma no soportado: {scheme}"

    try:
        # Decodificar componentes
        pubkey_bytes = base64.b64decode(signed_tx["pubkey_b64"])
        signature_bytes = base64.b64decode(signed_tx["signature_b64"])
        
        # Reconstruir mensaje canónico (el digest original)
        message_bytes = canonical_json_bytes(tx_data)

        # 2. Verificación Criptográfica
        verify_key = VerifyKey(pubkey_bytes)
        verify_key.verify(message_bytes, signature_bytes)

    except (ValueError, TypeError):
        return False, "Error de codificación Base64 en llaves o firma"
    except BadSignatureError:
        return False, "Firma digital inválida (integridad comprometida)"
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"

    # 3. Verificación de Dirección (Address Match)
    derived_address = address_from_pubkey(pubkey_bytes)
    claimed_address = tx_data.get("from")

    if derived_address != claimed_address:
        return False, f"Dirección no coincide. Pubkey genera {derived_address} pero dice ser {claimed_address}"

    # 4. Protección contra Replay (Nonce Check)
    tracker = _load_nonce_tracker()
    last_nonce = tracker.get(claimed_address, -1)
    current_nonce = int(tx_data.get("nonce", -1))

    if current_nonce <= last_nonce:
        return False, f"Nonce inválido o repetido ({current_nonce} <= {last_nonce})"

    return True, None

def commit_verification(signed_tx: Dict[str, Any]) -> None:
    """
    Marca una transacción verificada como aceptada actualizando el nonce tracker.

    Args:
        signed_tx (Dict[str, Any]): Paquete de transacción firmada que incluye el campo "tx" con los campos "from" y "nonce".

    Returns:
        None ( no devuelve nada ).

    Raises:
        KeyError: Si el paquete no contiene los campos esperados.
        OSError: Si ocurre un error al guardar el nonce tracker en disco.
    """
    sender = signed_tx["tx"]["from"]
    nonce = int(signed_tx["tx"]["nonce"])
    
    tracker = _load_nonce_tracker()
    tracker[sender] = nonce
    _save_nonce_tracker(tracker)