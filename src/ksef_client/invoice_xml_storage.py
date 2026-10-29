"""Private, immutable, hash-verified invoice files, with atomic no-clobber publication."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import stat
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from ._async_cleanup import shield_and_drain
from ._bounded_http import check_control
from .invoice_xml_types import (
    InvoiceXmlKey,
    InvoiceXmlReceipt,
    KsefXmlIntegrityError,
    KsefXmlStorageError,
    hash_bytes,
    positive_int,
    verify_hash,
)


def _safe_directory(path: Path, *, allow_missing: bool = False) -> None:
    for parent in (*reversed(path.parents), path):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if allow_missing:
                return
            raise
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise KsefXmlStorageError("unsafe_storage_path")


def _windows_handle(path: Path, *, directory: bool = False, create: bool = False) -> int:
    import ctypes
    from ctypes import wintypes

    kernel = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    handle = kernel.CreateFileW(
        str(path),
        0 if directory else (0x40000000 if create else 0x80000000),
        3 if directory else 1,
        None,
        1 if create else 3,
        0x00200000 | (0x02000000 if directory else 0),
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        error = cast(Any, ctypes).get_last_error()
        if error in (2, 3):
            raise FileNotFoundError
        if error in (80, 183):
            raise FileExistsError
        raise OSError(error, "Storage handle unavailable")
    attributes = (wintypes.DWORD * 2)()
    if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(attributes), 8):
        kernel.CloseHandle(handle)
        raise KsefXmlStorageError("storage_stat_failed")
    if attributes[0] & 0x400 or (not directory and attributes[0] & 0x10):
        kernel.CloseHandle(handle)
        raise KsefXmlStorageError("unsafe_storage_path")
    return int(handle)


class FileInvoiceXmlStore:
    """An application-owned private directory. Do not share it with untrusted writers."""

    def __init__(self, path: str | Path) -> None:
        self.root = Path(os.path.abspath(path))
        self._handles: list[int] = []
        self._dir_fd: int | None = None
        self._closed = False
        _safe_directory(self.root, allow_missing=True)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            _safe_directory(self.root)
            if os.name == "nt":
                # Deny directory rename/deletion, including ancestors, for our lifetime.
                for parent in (*reversed(self.root.parents), self.root):
                    self._handles.append(_windows_handle(parent, directory=True))
            else:
                self._dir_fd = os.open(
                    self.root,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
            try:
                with self._open(".storage-id") as stream:
                    identifier = stream.read(65).decode("ascii")
            except FileNotFoundError:
                identifier = uuid.uuid4().hex
                temp = ".tmp-" + uuid.uuid4().hex
                try:
                    with self._open(temp, create=True) as stream:
                        stream.write(identifier.encode("ascii"))
                        stream.flush()
                        os.fsync(stream.fileno())
                    self._publish(temp, ".storage-id")
                finally:
                    self._unlink(temp)
                with self._open(".storage-id") as stream:
                    identifier = stream.read(65).decode("ascii")
            if re.fullmatch("[a-f0-9]{32}", identifier) is None:
                raise KsefXmlStorageError("invalid_storage_id")
            self.storage_id = identifier
        except UnicodeError:
            self.close()
            raise KsefXmlStorageError("invalid_storage_id") from None
        except BaseException:
            self.close()
            raise

    def _open(self, name: str, *, create: bool = False) -> Any:
        if self._closed or "/" in name or "\\" in name or name in {".", ".."}:
            raise KsefXmlStorageError("unsafe_storage_path")
        if os.name == "nt":
            import msvcrt

            handle = _windows_handle(self.root / name, create=create)
            descriptor = cast(Any, msvcrt).open_osfhandle(
                handle, cast(Any, os).O_BINARY | (os.O_WRONLY if create else os.O_RDONLY)
            )
        else:
            flags = getattr(os, "O_NOFOLLOW", 0) | (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
            )
            flags |= getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(name, flags, 0o600, dir_fd=self._dir_fd)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise KsefXmlStorageError("unsafe_storage_file")
        return os.fdopen(descriptor, "wb" if create else "rb")

    def _unlink(self, name: str) -> None:
        with suppress(FileNotFoundError):
            if os.name == "nt":
                os.unlink(self.root / name)
            else:
                os.unlink(name, dir_fd=self._dir_fd)

    def _publish(self, source: str, target: str) -> None:
        try:
            if os.name == "nt":
                os.rename(self.root / source, self.root / target)
            else:
                os.link(
                    source,
                    target,
                    src_dir_fd=self._dir_fd,
                    dst_dir_fd=self._dir_fd,
                    follow_symlinks=False,
                )
                assert self._dir_fd is not None
                os.fsync(self._dir_fd)
        except FileExistsError:
            pass  # The caller must verify the winner before returning a receipt.

    def inspect(self, key: InvoiceXmlKey, expected_hash: str) -> InvoiceXmlReceipt | None:
        name = key.object_key(expected_hash)
        try:
            with self._open(name) as stream:
                digest, size = hashlib.sha256(), 0
                while chunk := stream.read(1024 * 1024):
                    check_control()
                    digest.update(chunk)
                    size += len(chunk)
            if digest.digest() != hash_bytes(expected_hash):
                raise KsefXmlIntegrityError("stored_hash_mismatch")
            return InvoiceXmlReceipt(self.storage_id, name, expected_hash, size)
        except FileNotFoundError:
            return None
        except OSError:
            raise KsefXmlStorageError("storage_read_failed") from None

    def put_verified(
        self, key: InvoiceXmlKey, content: bytes, expected_hash: str
    ) -> InvoiceXmlReceipt:
        verify_hash(content, expected_hash)
        existing = self.inspect(key, expected_hash)
        if existing is not None:
            return existing
        temp = ".tmp-" + uuid.uuid4().hex
        try:
            with self._open(temp, create=True) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            self._publish(temp, key.object_key(expected_hash))
        except OSError:
            raise KsefXmlStorageError("storage_write_failed") from None
        finally:
            self._unlink(temp)
        result = self.inspect(key, expected_hash)
        if result is None:
            raise KsefXmlStorageError("storage_publish_failed")
        return result

    def read(
        self, key: InvoiceXmlKey, expected_hash: str, *, max_bytes: int = 16 * 1024 * 1024
    ) -> bytes:
        positive_int(max_bytes, "max_bytes")
        try:
            with self._open(key.object_key(expected_hash)) as stream:
                content = stream.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise KsefXmlStorageError("stored_size_limit")
            verify_hash(content, expected_hash)
            return content
        except OSError:
            raise KsefXmlStorageError("storage_read_failed") from None

    def cleanup_staging(self, *, max_entries: int = 1000, older_than: float = 86400) -> int:
        positive_int(max_entries, "max_entries")
        if older_than < 120:
            raise ValueError("Staging retention must be at least 120 seconds")
        removed = 0
        with os.scandir(self.root) as entries:
            for index, entry in enumerate(entries):
                if index >= max_entries:
                    break
                if (
                    re.fullmatch(r"\.tmp-[a-f0-9]{32}", entry.name)
                    and entry.is_file(follow_symlinks=False)
                    and entry.stat(follow_symlinks=False).st_mtime < time.time() - older_than
                ):
                    self._unlink(entry.name)
                    removed += 1
        return removed

    def close(self) -> None:
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None
        if self._handles:
            import ctypes
            from ctypes import wintypes

            kernel = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            for handle in reversed(self._handles):
                kernel.CloseHandle(handle)
            self._handles.clear()
        self._closed = True

    def __enter__(self) -> FileInvoiceXmlStore:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AsyncFileInvoiceXmlStore:
    """Async file I/O runs outside the event loop; publications drain cancellation."""

    def __init__(self, store: FileInvoiceXmlStore) -> None:
        self._store = store
        self.storage_id = store.storage_id

    @classmethod
    async def open(cls, path: str | Path) -> AsyncFileInvoiceXmlStore:
        # Keep initialization owned until it can be closed even on cancellation.
        task = asyncio.create_task(asyncio.to_thread(FileInvoiceXmlStore, path))
        try:
            return cls(await asyncio.shield(task))
        except BaseException:

            async def cleanup() -> None:
                try:
                    store = await task
                except Exception:
                    return
                await asyncio.to_thread(store.close)

            await shield_and_drain(cleanup())
            raise

    async def inspect(self, key: InvoiceXmlKey, expected_hash: str) -> InvoiceXmlReceipt | None:
        return await shield_and_drain(asyncio.to_thread(self._store.inspect, key, expected_hash))

    async def put_verified(
        self, key: InvoiceXmlKey, content: bytes, expected_hash: str
    ) -> InvoiceXmlReceipt:
        return await shield_and_drain(
            asyncio.to_thread(self._store.put_verified, key, content, expected_hash)
        )

    async def read(self, key: InvoiceXmlKey, expected_hash: str) -> bytes:
        return await shield_and_drain(asyncio.to_thread(self._store.read, key, expected_hash))

    async def close(self) -> None:
        await shield_and_drain(asyncio.to_thread(self._store.close))

    async def cleanup_staging(self, *, max_entries: int = 1000, older_than: float = 86400) -> int:
        return await shield_and_drain(
            asyncio.to_thread(
                self._store.cleanup_staging,
                max_entries=max_entries,
                older_than=older_than,
            )
        )

    async def __aenter__(self) -> AsyncFileInvoiceXmlStore:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()
