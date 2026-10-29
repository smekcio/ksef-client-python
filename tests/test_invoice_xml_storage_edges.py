from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import threading
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from ksef_client import (
    AsyncSQLiteInvoiceSyncStore,
    FileInvoiceXmlStore,
    InvoiceXmlKey,
    KsefXmlStorageError,
)
from ksef_client import invoice_xml_storage as files
from tests.test_invoice_xml_sync import HASH, NUMBER, XML, environment


@pytest.mark.parametrize("error", [2, 3, 80, 183, 5])
def test_windows_handle_error_translation(monkeypatch, tmp_path, error):
    from ctypes import wintypes

    kernel = Mock()
    kernel.CreateFileW.return_value = wintypes.HANDLE(-1).value
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: kernel, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error, raising=False)
    expected = (
        FileNotFoundError if error in (2, 3) else FileExistsError if error in (80, 183) else OSError
    )
    with pytest.raises(expected):
        files._windows_handle(tmp_path / "file")


@pytest.mark.parametrize(
    "attributes,success,directory",
    [
        (0, True, False),
        (0x10, True, True),
        (0x400, True, False),
        (0x10, True, False),
        (0, False, False),
    ],
)
def test_windows_reparse_and_directory_checks(
    monkeypatch, tmp_path, attributes, success, directory
):
    kernel = Mock()
    kernel.CreateFileW.return_value = 123

    def information(handle, kind, pointer, size):
        pointer._obj[0] = attributes
        return success

    kernel.GetFileInformationByHandleEx.side_effect = information
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: kernel, raising=False)
    if success and not attributes & 0x400 and (directory or not attributes & 0x10):
        assert files._windows_handle(tmp_path / "file", directory=directory) == 123
    else:
        with pytest.raises(KsefXmlStorageError):
            files._windows_handle(tmp_path / "file", directory=directory)
        kernel.CloseHandle.assert_called_once_with(123)


@pytest.mark.skipif(os.name == "nt", reason="Portable Windows descriptor boundary simulation")
def test_windows_descriptor_adaptation_on_posix(monkeypatch, tmp_path):
    proxy = SimpleNamespace(**vars(os))
    proxy.name = "nt"
    monkeypatch.setattr(files, "os", proxy)
    monkeypatch.setitem(
        sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=lambda handle, flags: handle)
    )

    def handle(path, *, create=False):
        return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY if create else os.O_RDONLY, 0o600)

    monkeypatch.setattr(files, "_windows_handle", handle)
    storage = object.__new__(FileInvoiceXmlStore)
    storage._lock = threading.RLock()
    storage.root, storage._closed, storage._dir_fd, storage._handles = tmp_path, False, None, []
    proxy.O_BINARY = 0
    with storage._open("temporary", create=True) as stream:
        stream.write(b"bytes")
    storage._publish("temporary", "published")
    with storage._open("published") as stream:
        assert stream.read() == b"bytes"
    storage._unlink("published")
    storage.close()


def test_file_io_failures_do_not_report_publication(monkeypatch, tmp_path):
    key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
    with FileInvoiceXmlStore(tmp_path) as storage:
        original = storage._open

        def fail_write(name, *, create=False):
            if create:
                raise OSError("private-path")
            return original(name)

        monkeypatch.setattr(storage, "_open", fail_write)
        with pytest.raises(KsefXmlStorageError) as caught:
            storage.put_verified(key, XML, HASH)
        assert caught.value.reason_code == "storage_write_failed"
        monkeypatch.setattr(storage, "_open", original)
        monkeypatch.setattr(storage, "_publish", lambda *args: None)
        with pytest.raises(KsefXmlStorageError) as caught:
            storage.put_verified(key, XML, HASH)
        assert caught.value.reason_code == "storage_publish_failed"
        with pytest.raises(KsefXmlStorageError):
            storage.read(key, HASH)
        for name in ("../escape", "back\\slash", ".", ".."):
            with pytest.raises(KsefXmlStorageError):
                storage._open(name)


def test_async_initialization_cleanup_after_cancel(monkeypatch, tmp_path):
    original = files.FileInvoiceXmlStore
    started, release = threading.Event(), threading.Event()

    def slow(path):
        started.set()
        assert release.wait(10)
        return original(path)

    monkeypatch.setattr(files, "FileInvoiceXmlStore", slow)

    async def run():
        task = asyncio.create_task(files.AsyncFileInvoiceXmlStore.open(tmp_path))
        await asyncio.to_thread(started.wait, 10)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Closing drained the created store; no root directory locks remain.
        with original(tmp_path) as store:
            assert store.storage_id
        with pytest.raises(ValueError):
            await AsyncSQLiteInvoiceSyncStore.open(tmp_path / "db", enqueue_xml=True)

    asyncio.run(run())


def test_async_finish_drains_repeated_cancellation(tmp_path):
    async def run():
        async with environment(tmp_path, True) as (sync, store, storage, _):
            await sync.metadata.run_once(store)
            original = store.finish_xml
            started, release = asyncio.Event(), asyncio.Event()

            async def delayed(claim, receipt):
                started.set()
                await release.wait()
                return await original(claim, receipt)

            store.finish_xml = delayed
            task = asyncio.create_task(sync.xml.run_once(store, storage))
            await asyncio.wait_for(started.wait(), 10)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert (await store.describe_xml(sync.xml.scopes)).ready == 1

    asyncio.run(run())


@pytest.mark.skipif(os.name == "nt", reason="Windows storage lifecycle simulated on POSIX")
def test_windows_directory_handle_lifecycle(monkeypatch, tmp_path):
    proxy = SimpleNamespace(**vars(os))
    proxy.name, proxy.O_BINARY = "nt", 0
    monkeypatch.setattr(files, "os", proxy)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=lambda h, f: h))

    def handle(path, *, directory=False, create=False):
        flags = os.O_RDONLY if directory or not create else os.O_WRONLY | os.O_CREAT | os.O_EXCL
        return os.open(path, flags, 0o600)

    monkeypatch.setattr(files, "_windows_handle", handle)
    kernel = Mock()
    kernel.CloseHandle.side_effect = os.close
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: kernel, raising=False)
    with FileInvoiceXmlStore(tmp_path) as storage:
        assert storage._handles
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        storage.put_verified(key, XML, HASH)
        assert storage.read(key, HASH) == XML
    assert kernel.CloseHandle.call_count > 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO protection")
def test_special_file_rejected_without_blocking(tmp_path):
    with FileInvoiceXmlStore(tmp_path) as storage:
        cast(Any, os).mkfifo(tmp_path / "fifo")
        with pytest.raises(KsefXmlStorageError):
            storage._open("fifo")


def test_identifier_decode_and_failed_read_are_safe(monkeypatch, tmp_path):
    with FileInvoiceXmlStore(tmp_path) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)

        def unavailable(*args, **kwargs):
            raise PermissionError("private-storage-location")

        monkeypatch.setattr(storage, "_open", unavailable)
        with pytest.raises(KsefXmlStorageError):
            storage.inspect(key, HASH)
    (tmp_path / ".storage-id").write_bytes(b"\xff")
    with pytest.raises(KsefXmlStorageError):
        FileInvoiceXmlStore(tmp_path)


def test_async_file_context_and_failed_initialization(monkeypatch, tmp_path):
    async def run():
        async with await files.AsyncFileInvoiceXmlStore.open(tmp_path) as storage:
            assert await storage.cleanup_staging(max_entries=1) == 0

        def fail(path):
            raise OSError("creation failed")

        monkeypatch.setattr(files, "FileInvoiceXmlStore", fail)
        with pytest.raises(OSError):
            await files.AsyncFileInvoiceXmlStore.open(tmp_path / "other")

    asyncio.run(run())


def test_atomic_publication_loser_and_bounded_cleanup(tmp_path):
    with FileInvoiceXmlStore(tmp_path) as storage:
        key = InvoiceXmlKey("tenant", "0" * 64, "ctx", NUMBER)
        receipt = storage.put_verified(key, XML, HASH)
        temporary = ".tmp-" + "b" * 32
        with storage._open(temporary, create=True) as stream:
            stream.write(XML)
        storage._publish(temporary, receipt.object_key)
        storage._unlink(temporary)
        assert storage.read(key, HASH) == XML
        assert storage.cleanup_staging(max_entries=1) == 0
    with pytest.raises(FileNotFoundError):
        files._safe_directory(tmp_path / "missing")


def test_database_link_is_rejected_before_open(monkeypatch, tmp_path):
    from pathlib import Path

    target = tmp_path / "unsafe.db"
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == target or original(self))
    from ksef_client import SQLiteInvoiceSyncStore

    with pytest.raises(KsefXmlStorageError):
        SQLiteInvoiceSyncStore.open(target)
    assert not target.exists()
