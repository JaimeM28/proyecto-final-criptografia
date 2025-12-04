from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from .utils import canonical_json_bytes


def _now_iso_utc() -> str:
    """
    Genera una marca de tiempo UTC en formato ISO-8601.

    Returns:
        str: Cadena con la fecha y hora actual en UTC en formato ISO-8601.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Tx:
    """
    Modelo de transacción utilizado por la wallet.
    Contiene los campos esenciales para construir, serializar y firmar una transacción.

    Args:
        from_addr (str): Dirección de origen.
        to_addr (str): Dirección de destino.
        value (str): Valor a transferir, manejado como string para evitar problemas de deserialización.
        nonce (int): Nonce único de la transacción.
        gas_limit (int | None): Límite de gas opcional.
        data_hex (str | None): Payload opcional en formato hexadecimal.
        timestamp (str | None): Marca de tiempo; si no se proporciona, se genera automáticamente al serializar.
    """
    from_addr: str
    to_addr: str
    value: str          # lo manejamos como string
    nonce: int
    gas_limit: Optional[int] = None
    data_hex: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializa la transacción en un diccionario con valores adecuados para ser convertidos a JSON.

        Returns:
            Dict[str, Any]: Representación de la transacción como diccionario.
        """
        obj: Dict[str, Any] = {
            "from": self.from_addr,
            "to": self.to_addr,
            "value": self.value,
            "nonce": str(self.nonce),
            "timestamp": self.timestamp or _now_iso_utc(),
        }
        if self.gas_limit is not None:
            obj["gas_limit"] = str(self.gas_limit)
        if self.data_hex is not None:
            obj["data_hex"] = self.data_hex
        return obj

    def canonical_bytes(self) -> bytes:
        """
        Devuelve la representación canónica en bytes de la transacción.

        Returns:
            bytes: JSON canónico en bytes, listo para firma digital.
        """
        return canonical_json_bytes(self.to_dict())