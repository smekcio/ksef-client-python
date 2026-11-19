"""Private local output shared by the SDK and CLI."""

import os
import sys
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from typing import Any, BinaryIO, cast

from .invoice_xml_storage import _safe_directory, _windows_handle


def private_directory(path: Path) -> None:
    _safe_directory(path, allow_missing=True)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_directory(path)


@contextmanager
def _output_directory(parent: Path) -> Iterator[int | None]:
    """Pin the caller's directory until the output is published and staging cleaned up."""
    with ExitStack() as handles:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            close = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True).CloseHandle
            close.argtypes = [wintypes.HANDLE]
            for component in (*reversed(parent.parents), parent):
                handles.callback(close, _windows_handle(component, directory=True))
            yield None
        else:
            access = getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY))
            flags = access | os.O_DIRECTORY | os.O_NOFOLLOW
            directory = os.open(parent.anchor, flags)
            handles.callback(os.close, directory)
            for name in parent.parts[1:]:
                directory = os.open(name, flags, dir_fd=directory)
                handles.callback(os.close, directory)
            yield directory


@contextmanager
def private_output(path: Path, *, overwrite: bool = False) -> Iterator[BinaryIO]:
    destination = path.absolute()
    _safe_directory(destination.parent)
    with _output_directory(destination.parent) as directory:
        base = destination.parent if directory is None else Path(".")
        temporary = base / f".ksef-{uuid.uuid4().hex}"
        final = base / destination.name
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        fd = os.open(temporary, flags, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                yield stream
                stream.flush()
                os.fsync(stream.fileno())
            if directory is not None and not os.path.samestat(
                os.fstat(directory), destination.parent.lstat()
            ):
                raise OSError("Output directory changed during publication")
            if overwrite:
                os.replace(temporary, final, src_dir_fd=directory, dst_dir_fd=directory)
            elif directory is None:
                # On Windows rename never overwrites; it also works without hard-link support.
                os.rename(temporary, final)
            else:
                os.link(temporary, final, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)


def write_private_file(path: Path, content: bytes, *, overwrite: bool = False) -> None:
    with private_output(path, overwrite=overwrite) as stream:
        stream.write(content)
