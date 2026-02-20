from __future__ import annotations

from pathlib import Path


def create_sample_xml(path: Path) -> Path:
    path.write_text("<Faktura></Faktura>", encoding="utf-8")
    return path
