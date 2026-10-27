"""Final adversarial review: no credential leakage, unsafe replay, or unsafe disk writes."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import stat
import tarfile
import threading
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

import httpx
import pytest

from ksef_client import models as m
from ksef_client.async_facade import AsyncSession
from ksef_client.operations import KsefOperationError, OperationState
from ksef_client.streaming_export import (
    AsyncExportOperation,
    ExportOperation,
    KsefExportTransferError,
    decrypt_part,
    directory_lock,
    extract_archive,
    package_identity,
    part_identity,
    safe_path,
)
from tests.test_operations_facade import owner, state
from tests.test_streaming_export import IV, KEY, make_package, operation, sha
from tests.test_streaming_export import storage as storage


def test_state_rejects_path_injection_and_missing_invoice_parent():
    for ref in ["../escape", "REF?token=SECRET", "REF/other"]:
        with pytest.raises(ValueError):
            OperationState("permission", "env", "context", ref)
    with pytest.raises(ValueError):
        OperationState("invoice", "env", "context", "REF")


def test_windows_publication_retries_transient_sharing_violation(tmp_path):
    from ksef_client.streaming_export import publish_directory

    stage = tmp_path / "stage"
    target = tmp_path / "target"
    stage.mkdir()
    with patch.object(Path, "rename", side_effect=[PermissionError(), target]) as rename:
        publish_directory(stage, target)
        assert rename.call_count == 2
    with (
        patch.object(Path, "rename", side_effect=PermissionError()),
        pytest.raises(PermissionError),
    ):
        publish_directory(stage, target)
    target.mkdir()
    with pytest.raises(KsefExportTransferError):
        publish_directory(stage, target)


def test_posix_lock_is_released_and_links_are_rejected(tmp_path, monkeypatch):
    import ksef_client.streaming_export as module

    fake = SimpleNamespace(flock=Mock(), LOCK_EX=1, LOCK_NB=2, LOCK_UN=4)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(module.importlib, "import_module", lambda name: fake)
    with directory_lock(tmp_path):
        assert fake.flock.call_count == 1
    assert fake.flock.call_count == 2
    with (
        patch.object(Path, "is_symlink", return_value=True),
        pytest.raises(KsefExportTransferError),
    ):
        safe_path(tmp_path)


def test_windows_lock_protocol_is_verified_on_every_platform(tmp_path, monkeypatch):
    import ksef_client.streaming_export as module

    fake = SimpleNamespace(locking=Mock(), LK_NBLCK=1, LK_UNLCK=2)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    with patch.dict("sys.modules", {"msvcrt": fake}):
        with directory_lock(tmp_path):
            assert fake.locking.call_count == 1
        assert fake.locking.call_count == 2
        assert fake.locking.call_args.args[1:] == (fake.LK_UNLCK, 1)


@pytest.mark.parametrize("action", ["send", "upload", "close_started", "incomplete"])
def test_async_session_rejects_unsafe_actions(action):

    async def run():
        handle = Mock(
            reference_number="REF", part_upload_requests=[SimpleNamespace(ordinal_number=1)]
        )
        handle.get_state.return_value.to_dict.return_value = {}
        session = AsyncSession(owner(True), handle, batch=action != "upload")
        if action == "send":
            with pytest.raises(ValueError):
                await session.send_invoice(b"x")
        elif action == "upload":
            with pytest.raises(ValueError):
                await session.upload_parts()
        else:
            session._close_started = action == "close_started"
            with pytest.raises(KsefOperationError):
                await session.close()

    asyncio.run(run())


def test_malformed_crypto_and_parts_are_rejected_before_network():
    _, _, _, package = make_package(size=100)
    for payload in [
        {},
        {"key": "bad", "iv": "bad"},
        {"key": base64.b64encode(b"k").decode(), "iv": base64.b64encode(IV).decode()},
    ]:
        with pytest.raises(ValueError):
            ExportOperation(Mock(), state("export", **payload))
    with pytest.raises(KsefExportTransferError):
        part_identity(replace(package.parts[0], part_hash=base64.b64encode(b"x").decode()))
    with pytest.raises(KsefExportTransferError):
        package_identity(replace(package, parts=[package.parts[0]] * 10002))


def test_invalid_storage_url_does_not_echo_credentials():
    _, _, _, package = make_package(size=100)
    fake = Mock()
    fake.options = __import__("ksef_client", fromlist=["KsefClientOptions"]).KsefClientOptions(
        base_url="https://api-test.ksef.mf.gov.pl"
    )
    exported = ExportOperation(
        fake, state("export", key=base64.b64encode(KEY).decode(), iv=base64.b64encode(IV).decode())
    )
    with (
        patch("httpx.Request", side_effect=httpx.InvalidURL("SECRET")),
        pytest.raises(KsefExportTransferError) as caught,
        exported._stream(package.parts[0], {}),
    ):
        pytest.fail("Invalid URL reached the transport")
    assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize(
    "scenario",
    [
        "missing_package",
        "existing",
        "nested",
        "huge_checkpoint",
        "bad_progress",
        "archive_size",
        "corrupt",
        "oversize",
        "no_etag",
    ],
)
def test_fail_closed_transfer_variants(tmp_path, storage, scenario):
    _, _, encrypted, package = make_package(size=2 * 1024 * 1024)
    storage.body, storage.hash = (encrypted, sha(encrypted))
    op = operation(storage, package)
    target, work = (tmp_path / "result", tmp_path / "work")
    if scenario == "missing_package":
        op.owner.api.invoices.get_export_status.return_value = replace(
            op.owner.api.invoices.get_export_status.return_value, package=None
        )
    if scenario == "existing":
        target.mkdir()
    if scenario == "nested":
        target = work / "result"
    if scenario in {"huge_checkpoint", "bad_progress"}:
        op.download_to(target, work_dir=work)
        target = tmp_path / "second"
        if scenario == "huge_checkpoint":
            (work / "progress.json").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        else:
            (work / "part-1.bin").write_bytes(b"bad")
            raw = json.loads((work / "progress.json").read_text())
            raw["progress"]["1"] = []
            (work / "progress.json").write_text(json.dumps(raw))
    if scenario == "archive_size":
        op.owner.api.invoices.get_export_status.return_value = replace(
            op.owner.api.invoices.get_export_status.return_value,
            package=replace(package, size=package.size + 1),
        )
    if scenario == "corrupt":
        storage.body = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    if scenario == "oversize":
        op.owner.api.invoices.get_export_status.return_value = replace(
            op.owner.api.invoices.get_export_status.return_value,
            package=replace(
                package, parts=[replace(package.parts[0], encrypted_part_size=len(encrypted) - 16)]
            ),
        )
    if scenario == "no_etag":
        storage.etag = 'W/"weak"'
        storage.drops = 3
    try:
        with pytest.raises(KsefExportTransferError):
            op.download_to(target, work_dir=work)
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize("mode", ["refresh", "expired", "changed", "missing"])
def test_expired_signed_url_refreshes_only_the_same_part(tmp_path, storage, mode, caplog):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash, storage.mode = (encrypted, sha(encrypted), "forbidden")
    op = operation(storage, package)
    initial = op.owner.api.invoices.get_export_status.return_value
    count = 0

    def response(ref):
        nonlocal count
        count += 1
        if count > 1:
            if mode == "expired":
                return replace(initial, status=m.StatusInfo(code=210, description="expired"))
            if mode == "changed":
                return replace(
                    initial,
                    package=replace(package, parts=[replace(package.parts[0], part_size=2)]),
                )
            if mode == "missing":
                return replace(initial, package=replace(package, parts=[]))
            storage.mode = "normal"
        return initial

    op.owner.api.invoices.get_export_status.side_effect = response
    caplog.set_level("INFO")
    try:
        if mode == "refresh":
            op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        else:
            with pytest.raises(KsefExportTransferError):
                op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert "SECRET" not in caplog.text
    finally:
        op.owner.api.http_client.close()


def test_directory_race_never_overwrites_other_writer(tmp_path, storage, monkeypatch):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash = (encrypted, sha(encrypted))
    op = operation(storage, package)
    import ksef_client.streaming_export as module

    original = module.extract_archive
    target = tmp_path / "result"

    def extract(*args):
        result = original(*args)
        target.mkdir()
        (target / "other").write_text("keep")
        return result

    monkeypatch.setattr(module, "extract_archive", extract)
    try:
        with pytest.raises(KsefExportTransferError, match="already exists"):
            op.download_to(target, work_dir=tmp_path / "work")
        assert (target / "other").read_text() == "keep"
    finally:
        op.owner.api.http_client.close()


def test_archive_special_members_limits_and_truncated_payloads(tmp_path, monkeypatch):
    archive: Any
    entry: Any
    bad_compression: Any = "unsupported"
    from ksef_client.utils.zip_utils import build_zip

    output = tmp_path / "out"
    output.mkdir()
    path = tmp_path / "archive"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("dir/", b"")
        archive.writestr("dir/a.xml", b"x")
    assert extract_archive(path, output, m.CompressionType.ZIP) == ("dir/a.xml",)
    with zipfile.ZipFile(path, "w") as archive:
        entry = zipfile.ZipInfo("link")
        entry.external_attr = (stat.S_IFLNK | 511) << 16
        archive.writestr(entry, "target")
    with pytest.raises(KsefExportTransferError):
        extract_archive(path, output, m.CompressionType.ZIP)
    path.write_bytes(b"badzip")
    with pytest.raises(KsefExportTransferError):
        extract_archive(path, output, m.CompressionType.ZIP)
    path.write_bytes(build_zip({"big.xml": b"x" * 100000}))
    with pytest.raises(KsefExportTransferError, match="expansion"):
        extract_archive(path, output, m.CompressionType.ZIP)
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo("folder")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        archive.addfile(link)
    with pytest.raises(KsefExportTransferError):
        extract_archive(path, output, m.CompressionType.TARGZ)
    with pytest.raises(KsefExportTransferError):
        extract_archive(path, output, bad_compression)
    with tarfile.open(path, "w:gz") as archive:
        entry = tarfile.TarInfo("a.xml")
        entry.size = 1
        archive.addfile(entry, io.BytesIO(b"x"))
    with (
        patch.object(tarfile.TarFile, "extractfile", return_value=None),
        pytest.raises(KsefExportTransferError),
    ):
        extract_archive(path, output, m.CompressionType.TARGZ)

    class Short(io.BytesIO):
        def read(self, *args):
            return super().read(*args)

    class FakeZip:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def infolist(self):
            return [
                SimpleNamespace(
                    filename="short.xml",
                    file_size=3,
                    external_attr=0,
                    compress_type=zipfile.ZIP_STORED,
                    is_dir=lambda: False,
                )
            ]

        def open(self, entry):
            return Short(b"x")

    with (
        patch("ksef_client.streaming_export.validate_zip_directory"),
        patch("zipfile.ZipFile", return_value=FakeZip()),
        pytest.raises(KsefExportTransferError, match="inconsistent size"),
    ):
        extract_archive(path, output, m.CompressionType.ZIP)
    _, _, encrypted, package = make_package(size=100)
    path.write_bytes(encrypted)
    with pytest.raises(KsefExportTransferError):
        decrypt_part(path, io.BytesIO(), replace(package.parts[0], part_size=1), KEY, IV)


@pytest.mark.parametrize("cancel", [False, True, "deadline"])
def test_async_url_refresh_and_cancel_join_worker(tmp_path, storage, cancel):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash, storage.mode = (encrypted, sha(encrypted), "forbidden")
    sync = operation(storage, package)
    initial = sync.get_status()
    calls = 0
    entered = threading.Event()

    async def get_status(ref):
        nonlocal calls
        calls += 1
        if calls > 1:
            entered.set()
            if cancel == "deadline":
                raise TimeoutError("refresh deadline")
            await asyncio.sleep(5 if cancel else 0.08)
            storage.mode = "normal"
        return initial

    original = __import__("ksef_client.http", fromlist=["BaseHttpClient"]).BaseHttpClient

    def factory(options):
        result = original(options)
        result._client.close()
        result._client = httpx.Client(transport=storage.transport)
        return result

    async def run():
        owner = SimpleNamespace(
            options=sync.owner.options,
            api=SimpleNamespace(invoices=SimpleNamespace(get_export_status=get_status)),
        )
        op = AsyncExportOperation(owner, sync.resume_state())
        with patch("ksef_client.http.BaseHttpClient", side_effect=factory):
            task = asyncio.create_task(
                op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
            )
            while not entered.is_set():
                await asyncio.sleep(0.001)
            if cancel is True:
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert not (tmp_path / "result").exists()
            elif cancel == "deadline":
                with pytest.raises(TimeoutError, match="refresh deadline"):
                    await task
            else:
                assert (await task).files

    try:
        asyncio.run(run())
    finally:
        sync.owner.api.http_client.close()
