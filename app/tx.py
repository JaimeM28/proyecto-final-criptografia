from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from .utils import canonical_json_bytes


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Tx:
    from_addr: str
    to_addr: str
    value: str          # lo manejamos como string
    nonce: int
    gas_limit: Optional[int] = None
    data_hex: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
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
        return canonical_json_bytes(self.to_dict())