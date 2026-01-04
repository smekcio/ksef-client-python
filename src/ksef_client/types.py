from __future__ import annotations

from collections.abc import Mapping
from typing import Any

JsonDict = dict[str, Any]
JsonMapping = Mapping[str, Any]
Headers = Mapping[str, str]
QueryParams = Mapping[str, Any]

__all__ = [
    "JsonDict",
    "JsonMapping",
    "Headers",
    "QueryParams",
]
