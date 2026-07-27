from __future__ import annotations

import base64
import dataclasses
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


def to_jsonable(value: Any, *, max_repr: int = 1000) -> Any:
    """Convert common Python values to a deterministic JSON-compatible form.

    Unknown objects are represented by a bounded type-qualified repr. This is
    intended for audit metadata and action digests, not object round-tripping.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return str(value)
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return to_jsonable(value.value, max_repr=max_repr)
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"__type__": "bytes", "base64": base64.b64encode(value).decode("ascii")}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: to_jsonable(getattr(value, field.name), max_repr=max_repr)
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {
            str(key): to_jsonable(child, max_repr=max_repr)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [to_jsonable(child, max_repr=max_repr) for child in value]
    if isinstance(value, (set, frozenset)):
        converted = [to_jsonable(child, max_repr=max_repr) for child in value]
        return sorted(converted, key=lambda item: canonical_json(item))

    try:
        rendered = repr(value)
    except Exception:
        rendered = "<unreprable>"
    if len(rendered) > max_repr:
        rendered = rendered[: max_repr - 3] + "..."
    return {
        "__type__": f"{type(value).__module__}.{type(value).__qualname__}",
        "repr": rendered,
    }


def canonical_json(value: Any) -> str:
    return json.dumps(
        to_jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formulas while preserving numeric cells."""
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def markdown_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )
