from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from ksef_client import models as m
from ksef_client.async_facade import AsyncSession
from ksef_client.batch_outcomes import (
    BatchInvoice,
    BatchInvoiceManifest,
    prepare_invoice_batch,
)
from ksef_client.facade import Session
from ksef_client.invoice_xml_types import KsefXmlIntegrityError
from ksef_client.services.sessions import AsyncBatchSessionHandle, BatchSessionHandle
from ksef_client.utils.zip_utils import untar_gz_bytes_safe, unzip_bytes_safe

A = "5555555555-20250828-010080615740-E4"
FILES = {"accepted.xml": b"<a/>", "bad.xml": b"<b/>", "cancelled.xml": b"<c/>"}


def status(code=200, *, count=3, accepted=1, rejected=2):
    return m.SessionStatusResponse.from_dict(
        {
            "dateCreated": "start",
            "dateUpdated": "current",
            "status": {"code": code, "description": "session"},
            "invoiceCount": count,
            "successfulInvoiceCount": accepted,
            "failedInvoiceCount": rejected,
        }
    )


def remote(invoice, ordinal, *, code=200, ksef_number=None, name=None):
    return m.SessionInvoiceStatusResponse(
        status=m.StatusInfo(code, "invoice"),
        invoice_hash=invoice.invoice_hash,
        invoice_file_name=name,
        ksef_number=ksef_number,
        ordinal_number=ordinal,
        reference_number=f"invoice-{ordinal}",
        upo_download_url="https://storage.example/private",
    )


def outcome_values(report):
    return [row.disposition.value for row in report.invoices]


def setup_handle(manifest, remote_api, asynchronous):
    return (AsyncBatchSessionHandle if asynchronous else BatchSessionHandle)(
        _sessions=remote_api,
        _uploader=Mock(),
        reference_number="session",
        form_code=Mock(),
        batch_file=m.BatchFileInfo(
            file_size=manifest.file_size, file_hash=manifest.file_hash, file_parts=[]
        ),
        part_upload_requests=[],
        encryption_data=Mock(),
        _access_token="default",
    )


def read(handle, manifest, asynchronous, **kwargs):
    result = handle.invoice_outcomes(manifest, **kwargs)
    return asyncio.run(result) if asynchronous else result


@pytest.mark.parametrize(
    ("compression", "unpack"),
    [(m.CompressionType.ZIP, unzip_bytes_safe), (m.CompressionType.TARGZ, untar_gz_bytes_safe)],
)
def test_manifest_bound_to_exact_archive(compression, unpack):
    assert m.CompressionType.ZIP != m.CompressionType.TARGZ
    original = {"folder\\first.xml": b"<a/>", "second.XML": b"<b/>"}
    prepared = prepare_invoice_batch(original, compression_type=compression)
    assert unpack(prepared.archive_bytes) == {"folder/first.xml": b"<a/>", "second.XML": b"<b/>"}
    assert prepared.compression_type is compression
    assert BatchInvoiceManifest.from_dict(prepared.manifest.to_dict()) == prepared.manifest
    assert "first.xml" not in repr(prepared)
    assert "first.xml" not in repr(prepared.manifest.invoices[0])
    assert str(b"<a/>") not in repr(prepared)


@pytest.mark.parametrize(
    "files",
    [
        {},
        {"data.txt": b"x"},
        {"empty.xml": b""},
        {"one.xml": "bad"},
        {"nested/../doc.xml": b"abc"},
        {"dir\\doc.xml": b"a", "dir/doc.xml": b"b"},
        {"x" * 1025: b"x"},
        {42: b"x"},
    ],
)
def test_preparation_rejects_invalid_batch(files):
    with pytest.raises(ValueError):
        prepare_invoice_batch(files)


def test_compression_and_manifest_validation():
    manifest = prepare_invoice_batch(FILES).manifest
    serialized = manifest.to_dict()
    with pytest.raises(ValueError, match="compression"):
        prepare_invoice_batch(FILES, compression_type=m.CompressionType("other"))
    patches: tuple[dict[str, Any], ...] = (
        {"version": True},
        {"version": 2},
        {"invoices": []},
        {"invoices": {}},
        {"invoices": [{"file_name": "accepted.xml"}]},
        {"file_size": 0},
        {"invoices": [serialized["invoices"][0]] * 2},
        {"other_field": 1},
    )
    for patch in patches:
        with pytest.raises(ValueError):
            BatchInvoiceManifest.from_dict({**serialized, **patch})
    with pytest.raises(ValueError):
        BatchInvoiceManifest.from_dict(cast(Any, None))
    with pytest.raises(ValueError, match="manifest invoices"):
        replace(manifest, invoices=cast(Any, list(manifest.invoices)))
    with pytest.raises(ValueError, match="archive spelling"):
        BatchInvoice("folder\\one.xml", manifest.file_hash)
    with pytest.raises(KsefXmlIntegrityError):
        BatchInvoice("one.xml", "wrong hash")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_mixed_outcomes_pagination_readonly_and_retry_selection(asynchronous):
    remote_api = AsyncMock() if asynchronous else Mock()
    manifest = prepare_invoice_batch(FILES).manifest
    first, second, third = manifest.invoices
    # Report order is the source order even if KSeF returns the rows in another order.
    remote_api.get_session_status.return_value = status()
    remote_api.get_session_invoices.side_effect = [
        m.SessionInvoicesResponse([remote(third, 3, code=550)], "next"),
        m.SessionInvoicesResponse(
            [
                remote(first, 1, ksef_number=A),
                remote(second, 2, code=450, name=second.file_name),
            ]
        ),
    ]
    handle = setup_handle(manifest, remote_api, asynchronous)
    report = read(handle, manifest, asynchronous, access_token="override", page_size=10)
    assert outcome_values(report) == ["accepted", "rejected", "cancelled"]
    assert report.complete and report.session_status == 200
    assert report.invoices[0].ksef_number == A
    assert report.retry_candidates == (third,)
    assert report.correction_candidates == (second,)
    assert all(secret not in repr(report) for secret in (A, "storage.example", "accepted.xml"))
    assert remote_api.get_session_status.call_count == 2
    assert [call.kwargs for call in remote_api.get_session_invoices.call_args_list] == [
        {"continuation_token": None, "page_size": 10, "access_token": "override"},
        {"continuation_token": "next", "page_size": 10, "access_token": "override"},
    ]
    assert [call[0] for call in remote_api.method_calls] == [
        "get_session_status",
        "get_session_invoices",
        "get_session_invoices",
        "get_session_status",
    ]


def test_only_invoice_content_failures_are_correction_candidates():
    codes = (405, 410, 415, 430, 435, 450)
    manifest = prepare_invoice_batch({f"{code}.xml": str(code).encode() for code in codes}).manifest
    remote_api = Mock()
    remote_api.get_session_status.return_value = status(
        445, count=len(codes), accepted=0, rejected=len(codes)
    )
    remote_api.get_session_invoices.return_value = m.SessionInvoicesResponse(
        [
            remote(invoice, ordinal, code=code)
            for ordinal, (invoice, code) in enumerate(zip(manifest.invoices, codes, strict=True), 1)
        ]
    )
    handle = setup_handle(manifest, remote_api, False)
    report = read(handle, manifest, False)
    assert report.complete
    assert outcome_values(report) == ["rejected"] * len(codes)
    assert [outcome.status_code for outcome in report.invoices] == list(codes)
    assert [invoice.file_name for invoice in report.correction_candidates] == [
        "430.xml",
        "450.xml",
    ]
    assert report.retry_candidates == ()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "case", ["pending", "failed", "manifest", "size", "large_page", "page_count", "many_pages"]
)
def test_no_retry_when_results_are_not_authoritative(asynchronous, case):
    remote_api = AsyncMock() if asynchronous else Mock()
    manifest = prepare_invoice_batch(FILES).manifest
    handle = setup_handle(manifest, remote_api, asynchronous)
    args = {}
    remote_api.get_session_status.return_value = status()
    if case == "pending":
        remote_api.get_session_status.return_value = status(150)
    elif case == "failed":
        remote_api.get_session_status.return_value = status(430)
    elif case == "manifest":
        manifest = prepare_invoice_batch({"different.xml": b"x"}).manifest
    elif case == "size":
        manifest = replace(manifest, file_size=manifest.file_size + 1)
    elif case == "large_page":
        args = {"page_size": 1001}
    elif case == "page_count":
        args = {"max_pages": 0}
    else:
        args = {"max_pages": 1}
        remote_api.get_session_invoices.return_value = m.SessionInvoicesResponse(
            [remote(manifest.invoices[2], 3, code=550)], "cursor"
        )
    if case in {"manifest", "size", "large_page", "page_count"}:
        with pytest.raises(ValueError):
            read(handle, manifest, asynchronous, **args)
        remote_api.get_session_status.assert_not_called()
        return
    report = read(handle, manifest, asynchronous, **args)
    assert not report.complete and report.retry_candidates == report.correction_candidates == ()
    if case in {"pending", "failed"}:
        assert outcome_values(report) == ["unresolved"] * 3
        remote_api.get_session_invoices.assert_not_called()
    else:
        assert outcome_values(report) == ["unresolved", "unresolved", "cancelled"]


@pytest.mark.parametrize(
    ("problem", "expected"),
    [
        ("hash_mismatch", ["unresolved", "unresolved", "cancelled"]),
        ("bad_number", ["unresolved", "duplicate", "cancelled"]),
        ("duplicate_ref", ["unresolved", "unresolved", "cancelled"]),
        ("duplicate_ordinal", ["unresolved", "unresolved", "cancelled"]),
        ("duplicate_row", ["unresolved", "unresolved", "cancelled"]),
        ("duplicate_ksef_number", ["unresolved", "unresolved", "cancelled"]),
        ("bad_ordinal", ["unresolved", "duplicate", "cancelled"]),
        ("out_of_range_ordinal", ["accepted", "duplicate", "unresolved"]),
        ("missing_ordinal", ["unresolved", "duplicate", "cancelled"]),
        ("oversized", ["unresolved", "unresolved", "unresolved"]),
        ("bad_token", ["accepted", "duplicate", "cancelled"]),
        ("token_with_space", ["accepted", "duplicate", "cancelled"]),
        ("cyclic_token", ["accepted", "duplicate", "cancelled"]),
        ("no_reference", ["unresolved", "duplicate", "cancelled"]),
        ("unknown_status", ["unresolved", "duplicate", "cancelled"]),
        ("status_changed", ["accepted", "duplicate", "cancelled"]),
        ("count_conflict", ["accepted", "duplicate", "cancelled"]),
    ],
)
def test_inconsistent_api_results_are_never_resend_candidates(problem, expected):
    remote_api = Mock()
    manifest = prepare_invoice_batch(FILES).manifest
    first, second, third = manifest.invoices
    a, b, c = (
        remote(first, 1, ksef_number=A),
        remote(second, 2, code=440),
        remote(third, 3, code=550),
    )
    rows = [a, b, c]
    adverse_token = None
    initial = current = status()
    if problem == "hash_mismatch":
        rows[1] = replace(b, invoice_hash=a.invoice_hash, invoice_file_name=second.file_name)
    elif problem == "bad_number":
        rows[0] = replace(a, ksef_number="bad")
    elif problem == "duplicate_ref":
        rows[1] = replace(b, reference_number=a.reference_number)
    elif problem == "duplicate_ordinal":
        rows[1] = replace(b, ordinal_number=a.ordinal_number)
    elif problem == "duplicate_row":
        rows[1] = a
    elif problem == "duplicate_ksef_number":
        rows[1] = replace(b, status=a.status, ksef_number=A)
    elif problem == "bad_ordinal":
        rows[0] = replace(a, ordinal_number=0)
    elif problem == "out_of_range_ordinal":
        rows[2] = replace(c, ordinal_number=len(manifest.invoices) + 1)
    elif problem == "missing_ordinal":
        rows[0] = replace(a, ordinal_number=None)
    elif problem == "oversized":
        rows += [b]
    elif problem == "bad_token":
        adverse_token = "x" * 8193
    elif problem == "token_with_space":
        adverse_token = "not a token"
    elif problem == "cyclic_token":
        adverse_token = "again"
    elif problem == "no_reference":
        rows[0] = replace(a, reference_number=None)
    elif problem == "unknown_status":
        rows[0] = remote(first, 1, code=500)
    elif problem == "status_changed":
        current = status(150, count=None, accepted=None, rejected=None)
    elif problem == "count_conflict":
        initial = current = status(accepted=0)
    remote_api.get_session_status.side_effect = [initial, current]
    remote_api.get_session_invoices.side_effect = [
        m.SessionInvoicesResponse(rows, adverse_token),
        m.SessionInvoicesResponse([], adverse_token),
    ]
    report = read(setup_handle(manifest, remote_api, False), manifest, False)
    assert not report.complete
    assert outcome_values(report) == expected
    if problem in {"bad_token", "token_with_space"}:
        assert remote_api.get_session_invoices.call_count == 1
    assert report.retry_candidates == report.correction_candidates == ()


def test_identical_xml_requires_confirmed_filename_and_all_rejected_is_final():
    remote_api = Mock()
    manifest = prepare_invoice_batch({"one.xml": b"x", "two.xml": b"x"}).manifest
    first, second = manifest.invoices
    remote_api.get_session_status.return_value = status(445, count=2, accepted=0, rejected=2)
    remote_api.get_session_invoices.return_value = m.SessionInvoicesResponse(
        [
            remote(first, 1, code=450, name=first.file_name),
            remote(second, 2, code=550, name=second.file_name),
        ]
    )
    handle = setup_handle(manifest, remote_api, False)
    report = read(handle, manifest, False)
    assert report.complete
    assert outcome_values(report) == ["rejected", "cancelled"]
    assert report.retry_candidates == report.correction_candidates == ()
    remote_api.get_session_invoices.return_value = m.SessionInvoicesResponse(
        [remote(first, 1, code=450), remote(second, 2, code=550)]
    )
    report = read(handle, manifest, False)
    assert outcome_values(report) == ["unresolved"] * 2
    assert not report.complete and report.retry_candidates == ()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_facade_exposes_outcomes_for_batch_only(asynchronous):
    handle = AsyncMock() if asynchronous else Mock()
    manifest = prepare_invoice_batch(FILES).manifest
    session = SimpleNamespace(batch=True, handle=handle)
    method: Any = (AsyncSession if asynchronous else Session).invoice_outcomes
    result = method(session, manifest)
    report = asyncio.run(result) if asynchronous else result
    assert report is handle.invoice_outcomes.return_value
    handle.invoice_outcomes.assert_called_once_with(manifest, page_size=100, max_pages=100)
    session.batch = False
    with pytest.raises(ValueError, match="batch session"):
        result = method(session, manifest)
        if asynchronous:
            asyncio.run(result)
