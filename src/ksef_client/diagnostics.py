"""Explicit, bounded diagnostic redaction; transport serialization is unchanged."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from itertools import islice
from math import isfinite
from typing import Any

_SENSITIVE = frozenset(
    {
        "token",
        "accesstoken",
        "refreshtoken",
        "authenticationtoken",
        "kseftoken",
        "privatekey",
        "privatekeypem",
        "password",
        "secret",
        "clientsecret",
        "key",
        "symmetrickeybase64",
        "iv",
        "ivbase64",
        "headers",
        "customheaders",
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "apikey",
        "xapikey",
        "baseurl",
        "proxy",
        "baseqrurl",
        "baselighthouseurl",
        "url",
        "uploadurl",
        "downloadurl",
        "upodownloadurl",
        "content",
        "payload",
        "invoicexml",
        "responsebody",
        "cursor",
        "nextcursor",
        "lastcursor",
        "encryptedtoken",
        "encryptedsymmetrickey",
        "encryptedinvoicecontent",
        "initializationvector",
        "pkcs12password",
        "privatekeypassword",
        "invoicexmlfiles",
    }
)


def _sensitive(name: str) -> bool:
    return name.replace("_", "").replace("-", "").lower() in _SENSITIVE


def redact_sensitive(value: Any) -> Any:
    """Return bounded JSON diagnostics, never arbitrary objects' repr.

    Known secrets and fields hidden from repr are masked. The result is limited
    to depth 20, 1,000 visited nodes, 100 entries per container and 1,000 characters
    per string. Cycles and primitive subclasses are not passed to log formatters.
    This is not a persistence format or a scanner for secrets in free text.
    """
    active: set[int] = set()
    remaining = 1000

    def visit(item: Any, depth: int) -> Any:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            return "<node-limit>"
        if depth >= 20:
            return "<depth-limit>"
        if isinstance(item, Enum):
            return visit(item.value, depth + 1)
        if type(item) is str:
            return item if len(item) <= 1000 else item[:1000] + "<truncated>"
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            return item if item.bit_length() <= 4096 else "<large-int>"
        if type(item) is float:
            return item if isfinite(item) else "<non-finite>"
        dataclass = is_dataclass(item) and not isinstance(item, type)
        if not dataclass and type(item) not in (dict, list, tuple, set, frozenset):
            return f"<{type(item).__name__[:64]}>"
        if id(item) in active:
            return "<cycle>"
        active.add(id(item))
        try:
            if dataclass:
                model_fields = fields(item)
                result = {
                    f.name: "<redacted>"
                    if not f.repr or _sensitive(f.name)
                    else visit(getattr(item, f.name), depth + 1)
                    for f in model_fields[:100]
                }
                if len(model_fields) > 100:
                    result["<truncated>"] = True
                return result
            if type(item) is dict:
                result = {}
                for key, val in islice(item.items(), 100):
                    if type(key) is not str:
                        continue
                    if len(key) > 256:
                        result["<long-key>"] = "<redacted>"
                    else:
                        result[key] = "<redacted>" if _sensitive(key) else visit(val, depth + 1)
                if len(item) > 100:
                    result["<truncated>"] = True
                return result
            values = [visit(val, depth + 1) for val in islice(item, 100)]
            if len(item) > 100:
                values.append("<truncated>")
            return values
        finally:
            active.remove(id(item))

    return visit(value, 0)
