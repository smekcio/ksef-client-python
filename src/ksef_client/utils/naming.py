"""Wspólne narzędzia do konwersji nazw z kontraktu OpenAPI na atrybuty modeli.

Modele generowane z OpenAPI mają atrybuty w `snake_case`, a kontrakt nazywa je
`camelCase` (np. `invoiceSend` -> `invoice_send`, `KodWaluty` -> `kod_waluty`).
Konwersja jest potrzebna zarówno w warstwie usług, jak i w CLI, więc mieszka
w jednym miejscu.
"""

from __future__ import annotations

import re

_CAMEL_BOUNDARY_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_LOWER_UPPER_RE = re.compile(r"([a-z0-9])([A-Z])")


def to_snake_case(name: str) -> str:
    """Zamienia nazwę `camelCase`/`PascalCase` na `snake_case`.

    Obsługuje akronimy, żeby `invoiceExportStatus` dało `invoice_export_status`,
    a nie `invoice_export_status` z rozjechanym akronimem. Przypadki typu
    ``KodWaluty`` również są obsłużone.

    >>> to_snake_case("invoiceSend")
    'invoice_send'
    >>> to_snake_case("KodWaluty")
    'kod_waluty'
    """
    normalized = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", name)
    normalized = _LOWER_UPPER_RE.sub(r"\1_\2", normalized)
    return normalized.lower()
