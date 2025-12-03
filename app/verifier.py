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
    if not NONCE_TRACKER_PATH.exists():
        return {}
    try:
        with NONCE_TRACKER_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def _save_nonce_tracker(data: Dict[str, int]) -> None:
    with NONCE_TRACKER_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def verify_tx(signed_tx: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Verifica criptográficamente una transacción y valida contra ataques de replay.
    
    Pasos:
    1. Validar estructura y esquema de firma.
    2. Verificar firma Ed25519 sobre el JSON canónico.
    3. Verificar que la dirección 'from' corresponda a la llave pública.
    4. Verificar que el nonce sea mayor al último registrado (Replay Protection).
    
    Retorna: (EsValida, Razón_si_falla)
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
    Actualiza el rastreador de nonces una vez que la transacción se considera válida.
    """
    sender = signed_tx["tx"]["from"]
    nonce = int(signed_tx["tx"]["nonce"])
    
    tracker = _load_nonce_tracker()
    tracker[sender] = nonce
    _save_nonce_tracker(tracker)