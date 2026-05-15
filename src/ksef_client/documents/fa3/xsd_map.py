from __future__ import annotations

SUPPORTED_BUILDER_PATHS: dict[str, str] = {
    "/Faktura": "full typed FA(3) SDK coverage generated from XSD",
}

RAW_EXTENSION_PATHS: dict[str, str] = {}

UNSUPPORTED_PATHS: dict[str, str] = {}


__all__ = ["RAW_EXTENSION_PATHS", "SUPPORTED_BUILDER_PATHS", "UNSUPPORTED_PATHS"]
