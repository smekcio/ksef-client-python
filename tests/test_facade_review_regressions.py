"""Concrete SDK contracts and hostile inputs from the independent PR 109 review."""

from __future__ import annotations

import asyncio
import io
import os
import tarfile
import time
import tracemalloc
import zipfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from ksef_client import AsyncKsef, KsefClientOptions
from ksef_client import models as m
from ksef_client.async_facade import AsyncSession
from ksef_client.operations import KsefOperationTimeout
from ksef_client.services.crypto import EncryptionData
from ksef_client.services.sessions import AsyncBatchSessionHandle
from ksef_client.streaming_export import KsefExportTransferError, extract_archive
from tests.test_streaming_export import IV, KEY, make_package, operation, sha
from tests.test_streaming_export import storage as storage


@pytest.mark.parametrize("parallelism", [1, 3])
def test_async_batch_uses_real_handle_and_resumes_only_unconfirmed_parts(parallelism):
    async def run():
        active = peak = 0
        uploaded = []

        async def request(method, url, **kwargs):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.005)
            uploaded.append(url)
            active -= 1

        http = SimpleNamespace(request=request)
        api = Mock(http_client=http)
        owner = AsyncKsef(
            api,
            KsefClientOptions(base_url="https://example.test"),
            context_type="Nip",
            context_value="test",
        )
        requests = [
            m.PartUploadRequest(
                ordinal_number=i, method="PUT", url=f"https://storage.test/{i}", headers={}
            )
            for i in range(1, 5)
        ]
        sessions = SimpleNamespace(close_batch_session=AsyncMock())
        handle = AsyncBatchSessionHandle(
            sessions,
            Mock(),
            "BATCH",
            m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA"),
            m.BatchFileInfo(file_size=4, file_hash=sha(b"abcd"), file_parts=[]),
            requests,
            EncryptionData(KEY, IV, None),
            _encrypted_parts=[(i, b"x") for i in range(1, 5)],
        )
        session = AsyncSession(owner, handle, batch=True, completed_parts=[1])
        confirmed: list[int] = []
        async with session:
            await session.upload_parts(parallelism=parallelism, progress_callback=confirmed.append)
        assert peak == parallelism
        assert sorted(uploaded) == [f"https://storage.test/{i}" for i in range(2, 5)]
        assert sorted(confirmed) == [2, 3, 4]
        assert session.resume_state().payload["completed_parts"] == [1, 2, 3, 4]
        sessions.close_batch_session.assert_awaited_once()

    asyncio.run(run())


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_zip_rejects_unbounded_codecs_before_decompression(tmp_path, method):
    path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(path, "w", compression=method) as archive:
        archive.writestr("invoice.xml", b"x" * (32 * 1024 * 1024))
    target = tmp_path / "result"
    target.mkdir()
    tracemalloc.start()
    try:
        with pytest.raises(KsefExportTransferError, match="compression method"):
            extract_archive(path, target, m.CompressionType.ZIP)
        assert tracemalloc.get_traced_memory()[1] < 8 * 1024 * 1024
    finally:
        tracemalloc.stop()
    assert list(target.iterdir()) == []


def test_tar_rejects_large_pax_before_parser_allocation(tmp_path):
    path = tmp_path / "pax.tar.gz"
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        entry = tarfile.TarInfo("invoice.xml")
        entry.size = 1
        entry.pax_headers = {"comment": "x" * (16 * 1024 * 1024)}
        archive.addfile(entry, io.BytesIO(b"x"))
    target = tmp_path / "result"
    target.mkdir()
    tracemalloc.start()
    try:
        with pytest.raises(KsefExportTransferError, match="metadata"):
            extract_archive(path, target, m.CompressionType.TARGZ)
        assert tracemalloc.get_traced_memory()[1] < 8 * 1024 * 1024
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("format", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
def test_tar_preserves_bounded_extended_names(tmp_path, format):
    path = tmp_path / "names.tar.gz"
    name = "a" * 110 + ".xml"
    content = os.urandom(1024)
    with tarfile.open(path, "w:gz", format=format) as archive:
        entry = tarfile.TarInfo(name)
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))
    target = tmp_path / "result"
    target.mkdir()
    assert extract_archive(path, target, m.CompressionType.TARGZ) == (name,)
    assert (target / name).read_bytes() == content


@pytest.mark.parametrize("budget", ["headers", "members", "metadata"])
def test_tar_bounds_directories_headers_and_cumulative_metadata(tmp_path, monkeypatch, budget):
    import ksef_client.streaming_export as streaming

    path = tmp_path / "headers.tar.gz"
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for i in range(2):
            entry = tarfile.TarInfo(f"directory-{i}")
            entry.type = tarfile.DIRTYPE
            if budget == "metadata":
                entry.pax_headers = {"comment": "x" * 64}
            archive.addfile(entry)
    if budget == "metadata":
        monkeypatch.setattr(streaming, "TAR_MAX_METADATA", 128)
    else:
        monkeypatch.setattr(
            streaming, "EXPORT_MAX_ARCHIVE_ENTRIES", 0 if budget == "headers" else 1
        )
    target = tmp_path / "result"
    target.mkdir()
    with pytest.raises(KsefExportTransferError):
        extract_archive(path, target, m.CompressionType.TARGZ)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_trickling_storage_obeys_deadline_and_retains_resume_state(tmp_path, storage, asynchronous):
    from ksef_client.streaming_export import AsyncExportOperation

    _, _, encrypted, package = make_package(size=65536)
    storage.body, storage.hash, storage.mode = encrypted, sha(encrypted), "trickle"
    op = operation(storage, package)
    timeout = 0.15
    started = time.monotonic()
    try:
        with pytest.raises(KsefOperationTimeout) as caught:
            if asynchronous:
                async_op = AsyncExportOperation(op.owner, op.resume_state())
                async_op._fetch = AsyncMock(return_value=op.get_status())
                with patch(
                    "ksef_client.http.BaseHttpClient", return_value=op.owner.api.http_client
                ):
                    asyncio.run(
                        async_op.download_to(
                            tmp_path / "result", work_dir=tmp_path / "work", timeout=timeout
                        )
                    )
            else:
                op.download_to(tmp_path / "result", work_dir=tmp_path / "work", timeout=timeout)
        assert time.monotonic() - started < 0.7
        assert caught.value.state == op.resume_state()
        assert caught.value.last_status.status.code == 200
        assert not (tmp_path / "result").exists()
    finally:
        op.owner.api.http_client.close()


def test_tar_gzip_expansion_budget_includes_metadata_and_padding(tmp_path):
    path = tmp_path / "bomb.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        entry = tarfile.TarInfo("zeros.xml")
        entry.size = 1024 * 1024
        archive.addfile(entry, io.BytesIO(b"x" * entry.size))
    target = tmp_path / "result"
    target.mkdir()
    with pytest.raises(KsefExportTransferError, match="expansion"):
        extract_archive(path, target, m.CompressionType.TARGZ)


@pytest.mark.parametrize(
    "pax",
    [
        {"GNU.sparse.size": "1000000000000"},
        {"GNU.sparse.map": "0,1000000000000"},
        {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"},
    ],
)
def test_tar_rejects_pax_sparse_before_map_parsing(tmp_path, pax):
    path = tmp_path / "sparse.tar.gz"
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        entry = tarfile.TarInfo("sparse.xml")
        entry.pax_headers = pax
        archive.addfile(entry)
    target = tmp_path / "result"
    target.mkdir()
    with pytest.raises(KsefExportTransferError, match="Sparse"):
        extract_archive(path, target, m.CompressionType.TARGZ)


@pytest.mark.parametrize("corrupt", [False, True])
def test_tar_verifies_trailer_even_after_tar_end_marker(tmp_path, corrupt):
    import gzip

    path = tmp_path / "trailer.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        entry = tarfile.TarInfo("invoice.xml")
        entry.size = 64 * 1024
        archive.addfile(entry, io.BytesIO(os.urandom(entry.size)))
    # A legal padded TAR whose trailer lies beyond the stream parser's read-ahead.
    padded = gzip.decompress(path.read_bytes()) + b"\0" * (64 * 1024)
    data = bytearray(gzip.compress(padded))
    if corrupt:
        data[-8] ^= 1
    path.write_bytes(data)
    target = tmp_path / "result"
    target.mkdir()
    if corrupt:
        with pytest.raises(gzip.BadGzipFile):
            extract_archive(path, target, m.CompressionType.TARGZ)
    else:
        assert extract_archive(path, target, m.CompressionType.TARGZ) == ("invoice.xml",)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_download_parent_deadline_preserves_state_before_http(tmp_path, storage, asynchronous):
    from ksef_client.request_control import request_control
    from ksef_client.streaming_export import AsyncExportOperation

    _, _, _, package = make_package(size=100)
    op = operation(storage, package)
    try:
        # Windows Python 3.10-3.12 monotonic ticks can be about 15.6 ms apart.
        # Sleep across multiple ticks so expiration is independent of test order.
        with request_control(timeout_seconds=0.01):
            time.sleep(0.05)
            with pytest.raises(KsefOperationTimeout) as caught:
                if asynchronous:
                    asyncio.run(
                        AsyncExportOperation(op.owner, op.resume_state()).download_to(
                            tmp_path / "result", work_dir=tmp_path / "work"
                        )
                    )
                else:
                    op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert caught.value.state == op.resume_state()
        assert storage.requests == []
    finally:
        op.owner.api.http_client.close()
