"""Explicit, bounded diagnostic redaction; transport serialization is unchanged."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any

_SENSITIVE = frozenset({
    "token", "accesstoken", "refreshtoken", "authenticationtoken", "kseftoken",
    "privatekey", "privatekeypem", "password", "secret", "clientsecret", "key",
    "symmetrickeybase64", "iv", "ivbase64", "headers", "customheaders", "authorization",
    "url", "uploadurl", "downloadurl", "upodownloadurl", "content", "payload",
    "invoicexml", "responsebody", "cursor", "nextcursor", "lastcursor",
})


def _sensitive(name: str) -> bool:
    return name.replace("_", "").replace("-", "").lower() in _SENSITIVE


def redact_sensitive(value: Any) -> Any:
    """Return JSON-compatible diagnostics without calling unknown objects' repr.

    Known secret fields and dataclass fields hidden from repr are masked. Cycles
    and excessive nesting are bounded. This is not a persistence format and does
    not inspect arbitrary strings for embedded credentials.
    """
    def visit(item: Any, depth: int) -> Any:
        if depth >= 20:
            return "<depth-limit>"
        if isinstance(item, Enum):
            return visit(item.value, depth + 1)
        if item is None or isinstance(item, (str, bool, int, float)):
            return item
        if is_dataclass(item) and not isinstance(item, type):
            return {
                f.name: "<redacted>" if not f.repr or _sensitive(f.name)
                else visit(getattr(item, f.name), depth + 1)
                for f in fields(item)
            }
        if isinstance(item, dict):
            return {
                key: "<redacted>" if _sensitive(key) else visit(val, depth + 1)
                for key, val in item.items() if isinstance(key, str)
            }
        if isinstance(item, (list, tuple, set, frozenset)):
            return [visit(val, depth + 1) for val in item]
        return f"<{type(item).__name__}>"

    return visit(value, 0)
