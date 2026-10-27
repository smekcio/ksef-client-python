"""External-review regressions: disk limits, plaintext lifetime and resume safety."""

from __future__ import annotations

import asyncio
import json
import os
import zipfile
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ksef_client import ExportLimits
from ksef_client import models as m
from ksef_client.services.crypto import encrypt_aes_cbc_pkcs7
from ksef_client.streaming_export import (
    AsyncExportOperation,
    KsefExportTransferError,
    package_identity,
    part_identity,
    safe_path,
)
from tests.test_streaming_export import IV, KEY, make_package, operation, sha
from tests.test_streaming_export import storage as storage


@pytest.mark.parametrize("fail", [False, True])
def test_plaintext_archive_is_removed_after_success_and_failure(tmp_path, storage, fail):
    files, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash = encrypted, sha(encrypted)
    op = operation(storage, package)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    (work / "archive.bin").write_bytes(b"legacy plaintext")
    try:
        if fail:
            with (
                patch(
                    "ksef_client.streaming_export.extract_archive", side_effect=zipfile.BadZipFile
                ),
                pytest.raises(KsefExportTransferError) as caught,
            ):
                op.download_to(tmp_path / "result", work_dir=work)
            assert isinstance(caught.value.__cause__, zipfile.BadZipFile)
        else:
            result = op.download_to(tmp_path / "result", work_dir=work)
            assert (result.destination / "invoice.xml").read_bytes() == files["invoice.xml"]
        assert not (work / "archive.bin").exists()
        assert not list(tmp_path.glob(".ksef-export-*"))
        assert (work / "part-1.bin").read_bytes() == encrypted
    finally:
        op.owner.api.http_client.close()


def test_corrupt_checkpoint_has_a_domain_error_and_preserved_cause(tmp_path, storage):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash = encrypted, sha(encrypted)
    op = operation(storage, package)
    try:
        op.download_to(tmp_path / "first", work_dir=tmp_path / "work")
        (tmp_path / "work/progress.json").write_text("{broken", encoding="utf-8")
        with pytest.raises(KsefExportTransferError) as caught:
            op.download_to(tmp_path / "second", work_dir=tmp_path / "work")
        assert isinstance(caught.value.__cause__, json.JSONDecodeError)
        assert not (tmp_path / "second").exists()
    finally:
        op.owner.api.http_client.close()


def test_existing_public_work_directory_is_rejected(tmp_path, storage, monkeypatch):
    import ksef_client.streaming_export as module

    _, _, _, package = make_package(size=100)
    op = operation(storage, package)
    work = tmp_path / "work"
    work.mkdir(mode=0o755)
    work.chmod(0o755)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix", path=os.path))
    try:
        with pytest.raises(KsefExportTransferError, match="private"):
            op.download_to(tmp_path / "result", work_dir=work)
        assert storage.requests == []
    finally:
        op.owner.api.http_client.close()


def test_symlinked_parent_is_supported_but_final_symlink_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    assert safe_path(alias / "work") == real / "work"
    with pytest.raises(KsefExportTransferError, match="Links"):
        safe_path(alias)


@pytest.mark.parametrize("field", ["part_size", "encrypted_part_size"])
def test_terabyte_part_descriptors_are_rejected_before_transfer(field):
    part = make_package(size=100)[3].parts[0]
    with pytest.raises(KsefExportTransferError, match="size"):
        part_identity(replace(part, **{field: 10**12}))


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_transfer_limits_require_positive_integer_byte_counts(value):
    with pytest.raises(ValueError):
        ExportLimits(max_part_bytes=value)


def test_package_limits_include_sum_of_parts_and_cbc_padding():
    package = make_package(size=100)[3]
    with pytest.raises(KsefExportTransferError, match="size"):
        package_identity(package, ExportLimits(max_archive_bytes=1))
    with pytest.raises(KsefExportTransferError, match="size"):
        package_identity(replace(package, size=package.size + 1))
    with pytest.raises(KsefExportTransferError, match="CBC"):
        part_identity(replace(package.parts[0], encrypted_part_size=1))
    assert package_identity(package)
    with pytest.raises(KsefExportTransferError, match="invoice count"):
        package_identity(replace(package, invoice_count=10001))


@pytest.mark.parametrize("asynchronous", [False, True])
def test_limits_are_enforced_before_storage_http(tmp_path, storage, asynchronous):
    _, _, _, package = make_package(size=100)
    op = operation(storage, package)
    try:
        with pytest.raises(KsefExportTransferError, match="size"):
            if asynchronous:
                owner = SimpleNamespace(
                    options=op.owner.options,
                    api=SimpleNamespace(
                        invoices=SimpleNamespace(
                            get_export_status=AsyncMock(return_value=op.get_status())
                        )
                    ),
                )
                asyncio.run(
                    AsyncExportOperation(owner, op.resume_state()).download_to(
                        tmp_path / "result",
                        work_dir=tmp_path / "work",
                        limits=ExportLimits(max_archive_bytes=1),
                    )
                )
            else:
                op.download_to(
                    tmp_path / "result",
                    work_dir=tmp_path / "work",
                    limits=ExportLimits(max_archive_bytes=1),
                )
        assert storage.requests == []
    finally:
        op.owner.api.http_client.close()


def test_multipart_export_decrypts_in_ordinal_order(tmp_path, storage):
    files, archive, _, package = make_package(size=1000)
    split = len(archive) // 2
    chunks = [archive[:split], archive[split:]]
    bodies = {str(i): encrypt_aes_cbc_pkcs7(chunk, KEY, IV) for i, chunk in enumerate(chunks, 1)}
    parts = [
        replace(
            package.parts[0],
            ordinal_number=i,
            url=f"https://storage.example.test/{i}",
            part_size=len(chunk),
            part_hash=sha(chunk),
            encrypted_part_size=len(bodies[str(i)]),
            encrypted_part_hash=sha(bodies[str(i)]),
        )
        for i, chunk in enumerate(chunks, 1)
    ]
    package = replace(package, parts=list(reversed(parts)))
    op = operation(storage, package)

    def serve(request):
        body = bodies[request.url.path[1:]]
        return httpx.Response(
            200, headers={"x-ms-meta-hash": sha(body)}, stream=httpx.ByteStream(body)
        )

    op.owner.api.http_client._client.close()
    op.owner.api.http_client._client = httpx.Client(transport=httpx.MockTransport(serve))
    try:
        result = op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert (result.destination / "invoice.xml").read_bytes() == files["invoice.xml"]
        assert set(result.files) == set(files)
    finally:
        op.owner.api.http_client.close()


def test_invalid_download_options_do_not_start_polling(tmp_path, storage):
    op = operation(storage, make_package(size=100)[3])
    try:
        with pytest.raises(TypeError, match="ExportLimits"):
            op.download_to(tmp_path / "result", work_dir=tmp_path / "work", limits={})
        with pytest.raises(ValueError):
            op.download_to(tmp_path / "result", work_dir=tmp_path / "work", timeout=0)
        op.owner.api.invoices.get_export_status.assert_not_called()
    finally:
        op.owner.api.http_client.close()


def test_oversized_storage_body_is_stopped_before_publication(tmp_path, storage):
    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash = encrypted + b"excess", sha(encrypted)
    op = operation(storage, package)
    try:
        with pytest.raises(KsefExportTransferError, match="declared size"):
            op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert not (tmp_path / "result").exists()
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_pending_export_keeps_timeout_exception_type(tmp_path, storage, asynchronous):
    from ksef_client import KsefOperationTimeout

    op = operation(storage, make_package(size=100)[3])
    pending = m.InvoiceExportStatusResponse.from_dict(
        {"status": {"code": 100, "description": "pending"}}
    )
    op.owner.api.invoices.get_export_status.return_value = pending
    try:
        if asynchronous:
            owner = SimpleNamespace(
                options=op.owner.options,
                api=SimpleNamespace(
                    invoices=SimpleNamespace(get_export_status=AsyncMock(return_value=pending))
                ),
            )
            async_op = AsyncExportOperation(owner, op.resume_state())
            with pytest.raises(TypeError, match="ExportLimits"):
                asyncio.run(
                    async_op.download_to(
                        tmp_path / "out", work_dir=tmp_path / "work", limits=cast(Any, {})
                    )
                )
            with pytest.raises(KsefOperationTimeout):
                asyncio.run(
                    async_op.download_to(
                        tmp_path / "out",
                        work_dir=tmp_path / "work",
                        timeout=0.02,
                        poll_interval=0.005,
                    )
                )
        else:
            with pytest.raises(KsefOperationTimeout):
                op.download_to(
                    tmp_path / "out", work_dir=tmp_path / "work", timeout=0.02, poll_interval=0.005
                )
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize(
    "files,count,mode",
    [
        ((), 1, False),
        (("invoice.xml",), 1, False),
        (("_metadata.json",), 1, False),
        (("_metadata.json", "invoice.xml"), 1, True),
        (("_metadata.json", "unexpected.exe"), 1, None),
    ],
)
def test_package_contents_cannot_report_false_success(files, count, mode):
    from ksef_client.streaming_export import validate_export_files

    with pytest.raises(KsefExportTransferError):
        validate_export_files(files, count, mode)


@pytest.mark.parametrize("mode", [None, False])
def test_valid_package_contents_and_legacy_state_are_supported(mode):
    from ksef_client.streaming_export import validate_export_files

    validate_export_files(("_metadata.json", "invoice.xml"), 1, mode)
    validate_export_files(("_metadata.json",), 10, True)


def test_invalid_metadata_only_state_is_rejected_before_http(storage):
    from ksef_client.streaming_export import ExportOperation

    op = operation(storage, make_package(size=100)[3])
    state = op.resume_state().to_dict()
    state["payload"]["only_metadata"] = "invalid"
    try:
        from ksef_client import OperationState

        with pytest.raises(ValueError, match="metadata-only"):
            ExportOperation(op.owner, OperationState.from_dict(state))
        op.owner.api.invoices.get_export_status.assert_not_called()
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize("scenario", ["missing-metadata", "wrong-count", "metadata-only"])
def test_verified_storage_package_is_checked_before_publication(tmp_path, storage, scenario):
    from ksef_client import OperationState
    from ksef_client.streaming_export import ExportOperation
    from ksef_client.utils.zip_utils import build_zip

    files = {"_metadata.json": b"{}", "one.xml": os.urandom(100)}
    if scenario == "missing-metadata":
        del files["_metadata.json"]
    elif scenario == "wrong-count":
        files["two.xml"] = os.urandom(100)
    else:
        del files["one.xml"]
    archive = build_zip(files)
    encrypted = encrypt_aes_cbc_pkcs7(archive, KEY, IV)
    template = make_package(size=100)[3]
    part = replace(
        template.parts[0],
        part_size=len(archive),
        part_hash=sha(archive),
        encrypted_part_size=len(encrypted),
        encrypted_part_hash=sha(encrypted),
    )
    package = replace(template, size=len(archive), parts=[part])
    storage.body, storage.hash = encrypted, sha(encrypted)
    initial = operation(storage, package)
    saved = initial.resume_state().to_dict()
    saved["payload"]["only_metadata"] = scenario == "metadata-only"
    op = ExportOperation(initial.owner, OperationState.from_dict(saved))
    try:
        if scenario == "metadata-only":
            result = op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
            assert result.files == ("_metadata.json",)
        else:
            with pytest.raises(KsefExportTransferError):
                op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
            assert not (tmp_path / "result").exists()
        assert not (tmp_path / "work/archive.bin").exists()
    finally:
        op.owner.api.http_client.close()


def test_async_worker_initialization_errors_follow_the_transfer_contract(tmp_path, storage):
    op = operation(storage, make_package(size=100)[3])
    owner = SimpleNamespace(
        options=op.owner.options,
        api=SimpleNamespace(
            invoices=SimpleNamespace(get_export_status=AsyncMock(return_value=op.get_status()))
        ),
    )
    try:
        with (
            patch("ksef_client.http.BaseHttpClient", side_effect=OSError("transport setup")),
            pytest.raises(KsefExportTransferError) as caught,
        ):
            asyncio.run(
                AsyncExportOperation(owner, op.resume_state()).download_to(
                    tmp_path / "result", work_dir=tmp_path / "work"
                )
            )
        assert isinstance(caught.value.__cause__, OSError)
    finally:
        op.owner.api.http_client.close()


@pytest.mark.parametrize("entry", ["part-1.bin", "progress.json", ".lock", "archive.bin"])
def test_hard_linked_work_files_cannot_modify_other_files(tmp_path, storage, entry):
    op = operation(storage, make_package(size=100)[3])
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    victim = tmp_path / "other-file"
    victim.write_bytes(b"must remain unchanged")
    os.link(victim, work / entry)
    try:
        with pytest.raises(KsefExportTransferError, match="hard links"):
            op.download_to(tmp_path / "result", work_dir=work)
        assert victim.read_bytes() == b"must remain unchanged"
        assert storage.requests == []
    finally:
        op.owner.api.http_client.close()


def test_work_directories_are_not_accepted_as_regular_files(tmp_path):
    from ksef_client.streaming_export import safe_file

    with pytest.raises(KsefExportTransferError, match="regular files"):
        safe_file(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
def test_fifo_checkpoint_is_rejected_without_blocking(tmp_path, storage):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    fifo_factory = getattr(os, "mkfifo", None)
    assert fifo_factory is not None
    fifo_factory(work / "progress.json")
    op = operation(storage, make_package(size=100)[3])
    try:
        with pytest.raises(KsefExportTransferError, match="regular files"):
            op.download_to(tmp_path / "result", work_dir=work)
        assert storage.requests == []
    finally:
        op.owner.api.http_client.close()


def test_oversized_etag_does_not_inflate_checkpoint_or_prevent_download(tmp_path, storage):
    from ksef_client.streaming_export import strong_etag

    _, _, encrypted, package = make_package(size=100)
    storage.body, storage.hash, storage.etag = encrypted, sha(encrypted), '"' + "x" * 4096 + '"'
    assert not strong_etag(storage.etag)
    op = operation(storage, package)
    try:
        result = op.download_to(tmp_path / "result", work_dir=tmp_path / "work")
        assert result.files
        manifest = json.loads((tmp_path / "work/progress.json").read_text(encoding="utf-8"))
        assert manifest["progress"]["1"]["etag"] is None
        assert (tmp_path / "work/progress.json").stat().st_size < 4096
    finally:
        op.owner.api.http_client.close()
