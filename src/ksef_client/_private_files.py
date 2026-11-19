"""Private local output shared by the SDK and CLI."""

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from .invoice_xml_storage import _safe_directory


def private_directory(path: Path) -> None:
    _safe_directory(path, allow_missing=True)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_directory(path)


@contextmanager
def private_output(path: Path, *, overwrite: bool = False) -> Iterator[BinaryIO]:
    destination = path.absolute()
    _safe_directory(destination.parent)
    fd, name = tempfile.mkstemp(dir=destination.parent, prefix=".ksef-")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def write_private_file(path: Path, content: bytes, *, overwrite: bool = False) -> None:
    with private_output(path, overwrite=overwrite) as stream:
        stream.write(content)
