from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
import hashlib
import time
import uuid

from agent_roi._serialization import canonical_json, to_jsonable


def _stable_json(obj: Dict[str, Any]) -> str:
    return canonical_json(obj)


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    correlation_id: str
    run_id: str
    ts_epoch_ms: int
    event_type: str
    payload: Dict[str, Any]
    prev_hash: Optional[str] = None
    hash: Optional[str] = None

    @staticmethod
    def create(
        correlation_id: str,
        run_id: str,
        event_type: str,
        payload: Dict[str, Any],
        prev_hash: Optional[str],
        hash_chain: bool,
    ) -> "AuditEvent":
        safe_payload = to_jsonable(payload)
        if not isinstance(safe_payload, dict):
            safe_payload = {"value": safe_payload}
        base = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(correlation_id),
            "run_id": str(run_id),
            "ts_epoch_ms": int(time.time() * 1000),
            "event_type": str(event_type),
            "payload": safe_payload,
            "prev_hash": prev_hash,
        }
        event_hash = None
        if hash_chain:
            event_hash = hashlib.sha256(_stable_json(base).encode("utf-8")).hexdigest()

        return AuditEvent(
            event_id=base["event_id"],
            correlation_id=base["correlation_id"],
            run_id=base["run_id"],
            ts_epoch_ms=base["ts_epoch_ms"],
            event_type=base["event_type"],
            payload=safe_payload,
            prev_hash=prev_hash,
            hash=event_hash,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "run_id": self.run_id,
            "ts_epoch_ms": self.ts_epoch_ms,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }
