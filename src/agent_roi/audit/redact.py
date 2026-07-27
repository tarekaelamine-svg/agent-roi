from __future__ import annotations

from typing import Any, AbstractSet

DEFAULT_REDACTED_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "token",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "ssn",
    }
)


def redact(value: Any, *, blocked_keys: AbstractSet[str] = DEFAULT_REDACTED_KEYS) -> Any:
    """Recursively redact sensitive values using case-insensitive key matching."""
    normalized = {key.casefold() for key in blocked_keys}

    def _walk(item: Any) -> Any:
        if isinstance(item, dict):
            output = {}
            for key, child in item.items():
                key_text = str(key)
                output[key] = "[REDACTED]" if key_text.casefold() in normalized else _walk(child)
            return output
        if isinstance(item, list):
            return [_walk(child) for child in item]
        if isinstance(item, tuple):
            return tuple(_walk(child) for child in item)
        if isinstance(item, set):
            return sorted((_walk(child) for child in item), key=repr)
        return item

    return _walk(value)
