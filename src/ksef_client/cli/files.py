"""Private directories and atomic CLI output files."""

import os
import tempfile
from pathlib import Path

from ksef_client.invoice_xml_storage import _safe_directory


def private_directory(path: Path) -> None:
    _safe_directory(path, allow_missing=True)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_directory(path)


def write_private_file(path: Path, content: bytes, *, overwrite: bool = False) -> None:
    destination = path.absolute()
    _safe_directory(destination.parent)
    fd, name = tempfile.mkstemp(dir=destination.parent, prefix=".ksef-")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
