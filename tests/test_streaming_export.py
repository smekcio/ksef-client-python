"""Real HTTP transfer faults, disk restart, archive integrity, and async cancellation."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from ksef_client import KsefClientOptions
from ksef_client import models as m
from ksef_client.http import BaseHttpClient
from ksef_client.operations import OperationState
from ksef_client.services.crypto import encrypt_aes_cbc_pkcs7
from ksef_client.streaming_export import (
    AsyncExportOperation,
    ExportOperation,
    KsefExportTransferError,
    atomic_json,
    decrypt_part,
    extract_archive,
    package_identity,
    part_identity,
    strong_etag,
)
from ksef_client.utils.zip_utils import build_tar_gz, build_zip

KEY, IV = b"k" * 32, b"i" * 16


def sha(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def make_package(compression=m.CompressionType.ZIP, *, size=2 * 1024 * 1024 + 19):
    files = {"invoice.xml": os.urandom(size), "_metadata.json": b'{"isTruncated":false}'}
    archive = (build_zip if compression == m.CompressionType.ZIP else build_tar_gz)(files)
    encrypted = encrypt_aes_cbc_pkcs7(archive, KEY, IV)
    part = m.InvoicePackagePart(
        encrypted_part_hash=sha(encrypted),
        encrypted_part_size=len(encrypted),
        expiration_date="2099-01-01T00:00:00Z",
        method="GET",
        ordinal_number=1,
        part_hash=sha(archive),
        part_name="part1",
        part_size=len(archive),
        url="https://storage.example.test/part?sig=SECRET",
    )
    package = m.InvoicePackage(
        compression_type=compression,
        invoice_count=1,
        is_truncated=False,
        parts=[part],
        size=len(archive),
    )
    return files, archive, encrypted, package


@pytest.fixture
def storage():
    config = SimpleNamespace(
        body=b"", hash="", requests=[], mode="normal", drops=0, etag='"version1"'
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            config.requests.append(dict(self.headers))
            offset = int(self.headers.get("Range", "bytes=0-").split("=")[1].split("-")[0])
            mode = config.mode
            if mode == "forbidden":
                self.send_response(403)
                self.end_headers()
                return
            if mode == "retry":
                config.mode = "normal"
                self.send_response(503)
                self.send_header("Retry-After", "0")
                self.end_headers()
                return
            code = 206 if offset else 200
            if mode == "ignore":
                code, offset = 200, 0
            if offset and mode == "416":
                config.mode = "normal"
                self.send_response(416)
                self.end_headers()
                return
            self.send_response(code)
            self.send_header("Content-Length", str(len(config.body) - offset))
            self.send_header("ETag", config.etag)
            self.send_header("x-ms-meta-hash", config.hash)
            if mode == "encoded":
                self.send_header("Content-Encoding", "gzip")
            if code == 206:
                value = f"bytes {offset}-{len(config.body) - 1}/{len(config.body)}"
                if mode == "bad-range":
                    value = "bytes 0-1/2"
                    config.mode = "normal"
                self.send_header("Content-Range", value)
            self.end_headers()
            body = config.body[offset:]
            if config.drops:
                config.drops -= 1
                body = body[: 1024 * 1024]
                self.close_connection = True
            with suppress(ConnectionError, OSError):
                if mode == "trickle":
                    for offset in range(0, len(body), 1024):
                        self.wfile.write(body[offset : offset + 1024])
                        self.wfile.flush()
                        time.sleep(0.02)
                else:
                    self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    transport = httpx.HTTPTransport()

    class Relay(httpx.BaseTransport):
        def handle_request(self, request):
            # Only tests reroute the validated public storage URL to this local server.
            request.url = httpx.URL(f"http://127.0.0.1:{server.server_port}/part")
            return transport.handle_request(request)

        def close(self):
            pass

    config.transport = Relay()
    yield config
    transport.close()
    server.shutdown()
    server.server_close()
    thread.join()


def operation(storage, package):
    options = KsefClientOptions(
        base_url="https://api-test.ksef.mf.gov.pl",
        custom_headers={"Authorization": "SECRET", "Cookie": "SECRET", "X-Api-Key": "SECRET"},
    )
    http = BaseHttpClient(options)
    http._client.close()
    http._client = httpx.Client(transport=storage.transport)
    owner = SimpleNamespace(
        options=options,
        api=SimpleNamespace(
            http_client=http,
            invoices=SimpleNamespace(
                get_export_status=Mock(
                    return_value=m.InvoiceExportStatusResponse.from_dict(
                        {
                            "status": {"code": 200, "description": "ready"},
                            "package": package.to_dict(),
                        }
                    )
                )
            ),
        ),
    )
    state = OperationState(
        "export",
        "env",
        "context",
        "EXPORT",
        {"key": base64.b64encode(KEY).decode(), "iv": base64.b64encode(IV).decode()},
    )
    return ExportOperation(owner, state)


@pytest.mark.parametrize("compression", [m.CompressionType.ZIP, m.CompressionType.TARGZ])
def test_real_http_download_decrypt_extract_and_checkpoint_reuse(tmp_path, storage, compression):
    files, archive, encrypted, package = make_package(compression)
    storage.body, storage.hash = encrypted, sha(encrypted)
    op = operation(storage, package)
    try:
        result = op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert set(result.files) == set(files)
        assert result.metadata_path.read_bytes() == files["_metadata.json"]
        assert (result.destination / "invoice.xml").read_bytes() == files["invoice.xml"]
        assert "SECRET" not in (tmp_path / "work/progress.json").read_text()
        assert not any(
            k.lower() in {"authorization", "cookie", "x-api-key"} for k in storage.requests[0]
        )
        op = ExportOperation(op.owner, op.resume_state())
        op.download_to(tmp_path / "second", work_dir=tmp_path / "work")
        assert len(storage.requests) == 1
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize("mode", ["normal", "ignore", "bad-range", "416"])
def test_restart_uses_range_or_safely_restarts_part(tmp_path, storage, mode):
    _, _, encrypted, package = make_package(size=5 * 1024 * 1024)
    storage.body, storage.hash, storage.drops = encrypted, sha(encrypted), 3
    op = operation(storage, package)
    try:
        with pytest.raises(KsefExportTransferError, match="interrupted"):
            op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert not (tmp_path / "result").exists()
        assert (
            json.loads((tmp_path / "work/progress.json").read_text())["progress"]["1"]["offset"] > 0
        )
        storage.mode = mode
        resumed = ExportOperation(op.owner, op.resume_state())
        resumed.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert any(
            "Range" in headers and headers["If-Range"] == '"version1"'
            for headers in storage.requests
        )
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize("mode", ["encoded", "forbidden"])
def test_invalid_storage_never_publishes_result(tmp_path, storage, mode):
    _, _, encrypted, package = make_package(size=200)
    storage.body, storage.hash, storage.mode = encrypted, sha(encrypted), mode
    op = operation(storage, package)
    try:
        with pytest.raises(KsefExportTransferError):
            op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert not (tmp_path / "result").exists()
    finally:
        op.owner.api.http_client.close()


def test_storage_retry_and_bad_hash(tmp_path, storage):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash, storage.mode = encrypted, sha(encrypted), "retry"
    op = operation(storage, package)
    try:
        op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert len(storage.requests) == 2
        storage.hash = "BAD"
        with pytest.raises(KsefExportTransferError, match="hash"):
            op.download_to(tmp_path / "other", work_dir=tmp_path / "new-work")
    finally:
        op.owner.api.http_client.close()


def test_modified_partial_completed_part_and_checkpoint_are_revalidated(tmp_path, storage):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash = encrypted, sha(encrypted)
    op = operation(storage, package)
    try:
        op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        (tmp_path / "work/part-1.bin").write_bytes(b"BAD")
        op.download_to(tmp_path / "other", work_dir=tmp_path / "work")
        assert len(storage.requests) == 2
        raw = json.loads((tmp_path / "work/progress.json").read_text())
        raw["identity"]["reference"] = "OTHER"
        atomic_json(tmp_path / "work/progress.json", raw)
        with pytest.raises(KsefExportTransferError, match="different export"):
            op.download_to(tmp_path / "third", work_dir=tmp_path / "work")
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize(
    "name", ["../escape.xml", "/absolute.xml", "C:/drive.xml", "name.", "a\\..\\escape.xml"]
)
def test_archive_paths_are_rejected_without_external_writes(tmp_path, name):
    path = tmp_path / "archive.zip"
    import zipfile

    with zipfile.ZipFile(path, "w") as z:
        z.writestr(name, b"x")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises((ValueError, KsefExportTransferError)):
        extract_archive(path, out, m.CompressionType.ZIP)


def test_bad_padding_hash_and_part_descriptors(tmp_path):
    _, archive, encrypted, package = make_package(size=100)
    path = tmp_path / "part"
    path.write_bytes(encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
    with pytest.raises(KsefExportTransferError):
        decrypt_part(path, io.BytesIO(), package.parts[0], KEY, IV)
    from dataclasses import replace

    for part in [
        replace(package.parts[0], method="POST"),
        replace(package.parts[0], part_hash="bad"),
        replace(package.parts[0], part_hash=sha(b"other")),
    ]:
        with pytest.raises(KsefExportTransferError):
            if part.part_hash == sha(b"other"):
                path.write_bytes(encrypted)
                decrypt_part(path, io.BytesIO(), part, KEY, IV)
            else:
                part_identity(part)
    with pytest.raises(KsefExportTransferError):
        package_identity(replace(package, parts=[]))
    with pytest.raises(KsefExportTransferError):
        package_identity(replace(package, parts=[package.parts[0]] * 2))
    assert strong_etag('"etag"')
    for value in [None, 'W/"etag"', "bad", '"line\nfeed"']:
        assert not strong_etag(value)


def test_async_export_uses_worker_and_does_not_block_event_loop(tmp_path, storage):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash = encrypted, sha(encrypted)
    sync = operation(storage, package)
    async_owner = SimpleNamespace(
        options=sync.owner.options,
        api=SimpleNamespace(
            invoices=SimpleNamespace(get_export_status=AsyncMock(return_value=sync.get_status()))
        ),
    )
    original = BaseHttpClient

    def factory(options):
        result = original(options)
        result._client.close()
        result._client = httpx.Client(transport=storage.transport)
        return result

    async def run():
        operation = AsyncExportOperation(async_owner, sync.resume_state())
        ticks = []

        async def tick():
            for _ in range(10):
                ticks.append(1)
                await asyncio.sleep(0)

        with patch("ksef_client.http.BaseHttpClient", side_effect=factory):
            result, _ = await asyncio.gather(
                operation.download_to(tmp_path / "result", work_dir=tmp_path / "work"), tick()
            )
        assert result.files and len(ticks) == 10

    try:
        asyncio.run(run())
    finally:
        sync.owner.api.http_client.close()
