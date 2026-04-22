from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from ksef_client import models as m
from ksef_client.services.sessions import (
    AsyncBatchSessionHandle,
    BatchSessionHandle,
    BatchSessionState,
    OnlineSessionState,
)
from ksef_client.services.workflows import (
    AsyncBatchSessionWorkflow,
    AsyncBatchUploadHelper,
    AsyncOnlineSessionWorkflow,
    BatchSessionWorkflow,
    BatchUploadHelper,
    OnlineSessionHandle,
    OnlineSessionWorkflow,
)
from ksef_client.utils.zip_utils import build_zip
from tests.helpers import generate_rsa_cert


def _form_code() -> m.FormCode:
    return m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")


def _status_payload() -> m.SessionStatusResponse:
    return m.SessionStatusResponse.from_dict(
        {
            "dateCreated": "2026-04-01T12:00:00Z",
            "dateUpdated": "2026-04-01T12:01:00Z",
            "status": {"code": 200, "description": "OK"},
            "invoiceCount": 1,
            "successfulInvoiceCount": 1,
            "failedInvoiceCount": 0,
        }
    )


def _invoice_status_payload() -> m.SessionInvoiceStatusResponse:
    return m.SessionInvoiceStatusResponse.from_dict(
        {
            "status": {"code": 200, "description": "Accepted"},
            "referenceNumber": "INV-1",
            "invoiceHash": "hash",
            "invoicingDate": "2026-04-01T12:00:00Z",
            "ordinalNumber": 1,
        }
    )


def _open_online_session_response() -> m.OpenOnlineSessionResponse:
    return m.OpenOnlineSessionResponse.from_dict(
        {"referenceNumber": "SES-ONLINE-1", "validUntil": "2026-04-01T12:30:00Z"}
    )


def _open_batch_session_response(request_count: int) -> m.OpenBatchSessionResponse:
    return m.OpenBatchSessionResponse.from_dict(
        {
            "referenceNumber": "SES-BATCH-1",
            "partUploadRequests": [
                {
                    "ordinalNumber": index,
                    "url": f"https://upload/{index}",
                    "method": "PUT",
                    "headers": {"x-ms-blob-type": "BlockBlob"},
                }
                for index in range(1, request_count + 1)
            ],
        }
    )


@dataclass
class _RecordingHttp:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]]

    def __init__(self) -> None:
        self.calls = []

    def request(self, *args: Any, **kwargs: Any):
        self.calls.append((args, kwargs))
        return type("Response", (), {"content": b"", "headers": {}})()


@dataclass
class _RecordingAsyncHttp:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]]

    def __init__(self) -> None:
        self.calls = []

    async def request(self, *args: Any, **kwargs: Any):
        self.calls.append((args, kwargs))
        return type("Response", (), {"content": b"", "headers": {}})()


class _StubSessionsClient:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self._batch_requests = 0

    def open_online_session(self, payload, *, access_token=None, upo_v43=False):
        self.calls.append(("open_online", payload, access_token, upo_v43))
        return _open_online_session_response()

    def send_online_invoice(self, reference_number, request_payload, *, access_token=None):
        self.calls.append(("send_online", reference_number, request_payload, access_token))
        return m.SendInvoiceResponse.from_dict({"referenceNumber": "INV-1"})

    def close_online_session(self, reference_number, access_token=None):
        self.calls.append(("close_online", reference_number, access_token))

    def open_batch_session(self, payload, *, access_token=None, upo_v43=False):
        self.calls.append(("open_batch", payload, access_token, upo_v43))
        self._batch_requests = len(payload.batch_file.file_parts)
        return _open_batch_session_response(self._batch_requests)

    def close_batch_session(self, reference_number, access_token=None):
        self.calls.append(("close_batch", reference_number, access_token))

    def get_session_status(self, reference_number, access_token=None):
        self.calls.append(("status", reference_number, access_token))
        return _status_payload()

    def get_session_invoices(
        self, reference_number, *, page_size=None, continuation_token=None, access_token=None
    ):
        self.calls.append(("list", reference_number, page_size, continuation_token, access_token))
        return m.SessionInvoicesResponse.from_dict({"invoices": []})

    def get_session_failed_invoices(
        self, reference_number, *, page_size=None, continuation_token=None, access_token=None
    ):
        self.calls.append(
            ("list_failed", reference_number, page_size, continuation_token, access_token)
        )
        return m.SessionInvoicesResponse.from_dict({"invoices": []})

    def get_session_invoice_status(
        self, reference_number, invoice_reference_number, *, access_token=None
    ):
        self.calls.append(
            ("invoice_status", reference_number, invoice_reference_number, access_token)
        )
        return _invoice_status_payload()

    def get_session_invoice_upo_by_ref(
        self, reference_number, invoice_reference_number, *, access_token=None
    ):
        self.calls.append(
            ("invoice_upo_ref", reference_number, invoice_reference_number, access_token)
        )
        return b"<upo-by-ref/>"

    def get_session_invoice_upo_by_ksef(self, reference_number, ksef_number, *, access_token=None):
        self.calls.append(("invoice_upo_ksef", reference_number, ksef_number, access_token))
        return b"<upo-by-ksef/>"

    def get_session_upo(self, reference_number, upo_reference_number, *, access_token=None):
        self.calls.append(("session_upo", reference_number, upo_reference_number, access_token))
        return b"<upo-session/>"


class _StubAsyncSessionsClient(_StubSessionsClient):
    async def open_online_session(self, payload, *, access_token=None, upo_v43=False):
        return super().open_online_session(payload, access_token=access_token, upo_v43=upo_v43)

    async def send_online_invoice(self, reference_number, request_payload, *, access_token=None):
        return super().send_online_invoice(
            reference_number,
            request_payload,
            access_token=access_token,
        )

    async def close_online_session(self, reference_number, access_token=None):
        super().close_online_session(reference_number, access_token=access_token)

    async def open_batch_session(self, payload, *, access_token=None, upo_v43=False):
        return super().open_batch_session(payload, access_token=access_token, upo_v43=upo_v43)

    async def close_batch_session(self, reference_number, access_token=None):
        super().close_batch_session(reference_number, access_token=access_token)

    async def get_session_status(self, reference_number, access_token=None):
        return super().get_session_status(reference_number, access_token=access_token)

    async def get_session_invoices(
        self, reference_number, *, page_size=None, continuation_token=None, access_token=None
    ):
        return super().get_session_invoices(
            reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=access_token,
        )

    async def get_session_failed_invoices(
        self, reference_number, *, page_size=None, continuation_token=None, access_token=None
    ):
        return super().get_session_failed_invoices(
            reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=access_token,
        )

    async def get_session_invoice_status(
        self, reference_number, invoice_reference_number, *, access_token=None
    ):
        return super().get_session_invoice_status(
            reference_number,
            invoice_reference_number,
            access_token=access_token,
        )

    async def get_session_invoice_upo_by_ref(
        self, reference_number, invoice_reference_number, *, access_token=None
    ):
        return super().get_session_invoice_upo_by_ref(
            reference_number,
            invoice_reference_number,
            access_token=access_token,
        )

    async def get_session_invoice_upo_by_ksef(
        self, reference_number, ksef_number, *, access_token=None
    ):
        return super().get_session_invoice_upo_by_ksef(
            reference_number,
            ksef_number,
            access_token=access_token,
        )

    async def get_session_upo(self, reference_number, upo_reference_number, *, access_token=None):
        return super().get_session_upo(
            reference_number,
            upo_reference_number,
            access_token=access_token,
        )


def test_online_session_state_roundtrip_and_validation() -> None:
    state = OnlineSessionState(
        reference_number="SES-1",
        form_code=_form_code(),
        valid_until="2026-04-01T12:30:00Z",
        symmetric_key_base64="AQID",
        iv_base64="BAUG",
        upo_v43=True,
    )
    restored = OnlineSessionState.from_dict(state.to_dict())
    assert restored == state
    assert OnlineSessionState.from_json(state.to_json()) == state

    with pytest.raises(ValueError):
        OnlineSessionState.from_dict(state.to_dict() | {"schema_version": 2})
    with pytest.raises(ValueError):
        OnlineSessionState.from_dict(state.to_dict() | {"kind": "batch"})
    with pytest.raises(ValueError):
        OnlineSessionState.from_dict(state.to_dict() | {"symmetric_key_base64": "???"})


def test_batch_session_state_roundtrip_and_validation() -> None:
    batch_file = m.BatchFileInfo.from_dict(
        {
            "fileSize": 10,
            "fileHash": "hash",
            "fileParts": [{"ordinalNumber": 1, "fileSize": 10, "fileHash": "hash-part"}],
        }
    )
    request = m.PartUploadRequest.from_dict(
        {
            "ordinalNumber": 1,
            "url": "https://upload/1",
            "method": "PUT",
            "headers": {"x": "y"},
        }
    )
    state = BatchSessionState(
        reference_number="SES-BATCH",
        form_code=_form_code(),
        batch_file=batch_file,
        part_upload_requests=[request],
        symmetric_key_base64="AQID",
        iv_base64="BAUG",
        upo_v43=False,
        offline_mode=True,
    )
    restored = BatchSessionState.from_dict(state.to_dict())
    assert restored == state
    assert BatchSessionState.from_json(state.to_json()) == state

    with pytest.raises(ValueError):
        BatchSessionState.from_dict(state.to_dict() | {"kind": "online"})
    with pytest.raises(ValueError):
        BatchSessionState.from_dict(state.to_dict() | {"iv_base64": "###"})


def test_session_states_cover_validation_error_paths() -> None:
    with pytest.raises(ValueError):
        OnlineSessionState.from_json("[]")
    with pytest.raises(ValueError):
        OnlineSessionState(
            reference_number="SES-1",
            form_code=_form_code(),
            valid_until="2026-04-01T12:30:00Z",
            symmetric_key_base64="AQID",
            iv_base64="BAUG",
            schema_version=2,
        )
    with pytest.raises(ValueError):
        OnlineSessionState(
            reference_number="SES-1",
            form_code=_form_code(),
            valid_until="2026-04-01T12:30:00Z",
            symmetric_key_base64="AQID",
            iv_base64="BAUG",
            kind="batch",
        )

    online_state = OnlineSessionState(
        reference_number="SES-1",
        form_code=_form_code(),
        valid_until="2026-04-01T12:30:00Z",
        symmetric_key_base64="AQID",
        iv_base64="BAUG",
    )
    with pytest.raises(ValueError):
        OnlineSessionState.from_dict(online_state.to_dict() | {"reference_number": " "})
    with pytest.raises(ValueError):
        OnlineSessionState.from_dict(online_state.to_dict() | {"valid_until": 1})
    with pytest.raises(ValueError):
        OnlineSessionState.from_dict(online_state.to_dict() | {"symmetric_key_base64": 1})
    with pytest.raises(ValueError):
        OnlineSessionState.from_dict(online_state.to_dict() | {"iv_base64": 1})

    batch_state = BatchSessionState(
        reference_number="SES-BATCH",
        form_code=_form_code(),
        batch_file=m.BatchFileInfo.from_dict(
            {
                "fileSize": 10,
                "fileHash": "hash",
                "fileParts": [{"ordinalNumber": 1, "fileSize": 10, "fileHash": "hash-part"}],
            }
        ),
        part_upload_requests=[
            m.PartUploadRequest.from_dict(
                {
                    "ordinalNumber": 1,
                    "url": "https://upload/1",
                    "method": "PUT",
                    "headers": {},
                }
            )
        ],
        symmetric_key_base64="AQID",
        iv_base64="BAUG",
    )
    with pytest.raises(ValueError):
        BatchSessionState(
            reference_number=batch_state.reference_number,
            form_code=batch_state.form_code,
            batch_file=batch_state.batch_file,
            part_upload_requests=batch_state.part_upload_requests,
            symmetric_key_base64=batch_state.symmetric_key_base64,
            iv_base64=batch_state.iv_base64,
            schema_version=2,
        )
    with pytest.raises(ValueError):
        BatchSessionState(
            reference_number=batch_state.reference_number,
            form_code=batch_state.form_code,
            batch_file=batch_state.batch_file,
            part_upload_requests=batch_state.part_upload_requests,
            symmetric_key_base64=batch_state.symmetric_key_base64,
            iv_base64=batch_state.iv_base64,
            kind="online",
        )
    with pytest.raises(ValueError):
        BatchSessionState.from_dict(batch_state.to_dict() | {"reference_number": " "})
    with pytest.raises(ValueError):
        BatchSessionState.from_dict(batch_state.to_dict() | {"symmetric_key_base64": 1})
    with pytest.raises(ValueError):
        BatchSessionState.from_dict(batch_state.to_dict() | {"iv_base64": 1})
    with pytest.raises(ValueError):
        BatchSessionState.from_dict(batch_state.to_dict() | {"offline_mode": "yes"})
    with pytest.raises(ValueError):
        BatchSessionState.from_dict(batch_state.to_dict() | {"part_upload_requests": {}})


def test_online_workflow_returns_handle_and_resume_supports_status_methods() -> None:
    sessions = _StubSessionsClient()
    workflow = OnlineSessionWorkflow(sessions)
    rsa_cert = generate_rsa_cert()

    session = workflow.open_session(
        form_code=_form_code(),
        public_certificate=rsa_cert.certificate_pem,
        access_token="token",
        upo_v43=True,
    )

    assert isinstance(session, OnlineSessionHandle)
    assert session.session_reference_number == "SES-ONLINE-1"
    assert session.get_status(access_token="override").status.code == 200

    resumed = workflow.resume_session(session.get_state(), access_token="token")
    assert resumed.get_invoice_status("INV-1").reference_number == "INV-1"
    assert resumed.get_invoice_upo_by_ref("INV-1") == b"<upo-by-ref/>"
    assert resumed.get_invoice_upo_by_ksef("KSEF-1") == b"<upo-by-ksef/>"
    assert resumed.get_upo("UPO-1") == b"<upo-session/>"
    resumed.close()


def test_online_handle_send_and_list_operations_cover_sync_paths() -> None:
    sessions = _StubSessionsClient()
    workflow = OnlineSessionWorkflow(sessions)
    rsa_cert = generate_rsa_cert()

    session = workflow.open_session(
        form_code=_form_code(),
        public_certificate=rsa_cert.certificate_pem,
        access_token="token",
    )

    response = session.send_invoice(
        b"<faktura/>",
        offline_mode=True,
        hash_of_corrected_invoice="HASH-1",
    )

    assert response.reference_number == "INV-1"
    assert session.list_invoices().invoices == []
    assert session.list_failed_invoices().invoices == []


def test_batch_workflow_resume_validates_zip_and_upload_progress() -> None:
    sessions = _StubSessionsClient()
    http = _RecordingHttp()
    workflow = BatchSessionWorkflow(sessions, http)
    rsa_cert = generate_rsa_cert()
    zip_bytes = build_zip({"a.xml": b"<a/>", "b.xml": b"<b/>"})

    session = workflow.open_session(
        form_code=_form_code(),
        zip_bytes=zip_bytes,
        public_certificate=rsa_cert.certificate_pem,
        access_token="token",
        upo_v43=True,
    )

    uploaded_ordinals: list[int] = []
    session.upload_parts(
        parallelism=2,
        progress_callback=lambda ordinal: uploaded_ordinals.append(ordinal),
    )
    assert uploaded_ordinals == [1]
    assert len(http.calls) == 1

    resumed = workflow.resume_session(
        session.get_state(),
        zip_bytes=zip_bytes,
        access_token="token",
    )
    resumed.upload_parts(progress_callback=lambda ordinal: uploaded_ordinals.append(ordinal))
    assert uploaded_ordinals[-1:] == [1]
    resumed.close()

    with pytest.raises(ValueError):
        workflow.resume_session(
            session.get_state(),
            zip_bytes=build_zip({"changed.xml": b"<x/>"}),
            access_token="token",
        )


def test_batch_handle_from_state_without_zip_covers_error_and_status_methods() -> None:
    sessions = _StubSessionsClient()
    uploader = BatchUploadHelper(_RecordingHttp())
    state = BatchSessionState(
        reference_number="SES-BATCH-1",
        form_code=_form_code(),
        batch_file=m.BatchFileInfo.from_dict(
            {
                "fileSize": 10,
                "fileHash": "hash",
                "fileParts": [{"ordinalNumber": 1, "fileSize": 10, "fileHash": "hash-part"}],
            }
        ),
        part_upload_requests=[
            m.PartUploadRequest.from_dict(
                {
                    "ordinalNumber": 1,
                    "url": "https://upload/1",
                    "method": "PUT",
                    "headers": {},
                }
            )
        ],
        symmetric_key_base64="AQID",
        iv_base64="BAUG",
    )

    handle = BatchSessionHandle.from_state(
        state,
        sessions_client=sessions,
        uploader=uploader,
        access_token="token",
    )

    assert handle.session_reference_number == "SES-BATCH-1"
    assert handle.get_status().status.code == 200
    assert handle.list_invoices().invoices == []
    assert handle.list_failed_invoices().invoices == []
    assert handle.get_upo("UPO-1") == b"<upo-session/>"
    with pytest.raises(ValueError):
        handle.upload_parts()


def test_async_online_workflow_resume_supports_handle_methods() -> None:
    async def _run() -> None:
        sessions = _StubAsyncSessionsClient()
        workflow = AsyncOnlineSessionWorkflow(sessions)
        rsa_cert = generate_rsa_cert()

        session = await workflow.open_session(
            form_code=_form_code(),
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
        )
        await session.send_invoice(b"<faktura/>")
        resumed = workflow.resume_session(session.get_state(), access_token="token")
        status = await resumed.get_status()
        assert status.status.code == 200
        await resumed.close()

    asyncio.run(_run())


def test_async_online_handle_covers_listing_and_upo_methods() -> None:
    async def _run() -> None:
        sessions = _StubAsyncSessionsClient()
        workflow = AsyncOnlineSessionWorkflow(sessions)
        rsa_cert = generate_rsa_cert()

        session = await workflow.open_session(
            form_code=_form_code(),
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
        )

        assert session.session_reference_number == "SES-ONLINE-1"
        await session.list_invoices()
        await session.list_failed_invoices()
        assert (await session.get_invoice_status("INV-1")).reference_number == "INV-1"
        assert await session.get_invoice_upo_by_ref("INV-1") == b"<upo-by-ref/>"
        assert await session.get_invoice_upo_by_ksef("KSEF-1") == b"<upo-by-ksef/>"
        assert await session.get_upo("UPO-1") == b"<upo-session/>"

    asyncio.run(_run())


def test_async_batch_upload_helper_supports_skip_and_progress() -> None:
    async def _run() -> None:
        http = _RecordingAsyncHttp()
        helper = AsyncBatchUploadHelper(http)
        requests = [
            m.PartUploadRequest.from_dict(
                {
                    "ordinalNumber": 1,
                    "url": "https://upload/1",
                    "method": "PUT",
                    "headers": {},
                }
            ),
            m.PartUploadRequest.from_dict(
                {
                    "ordinalNumber": 2,
                    "url": "https://upload/2",
                    "method": "PUT",
                    "headers": {},
                }
            ),
        ]
        seen: list[int] = []

        await helper.upload_parts(
            requests,
            [(1, b"a"), (2, b"b")],
            skip_ordinals={1},
            progress_callback=lambda ordinal: seen.append(ordinal),
        )

        assert seen == [2]
        assert len(http.calls) == 1

    asyncio.run(_run())


def test_async_batch_workflow_resume_covers_handle_methods_and_validation() -> None:
    async def _run() -> None:
        sessions = _StubAsyncSessionsClient()
        http = _RecordingAsyncHttp()
        workflow = AsyncBatchSessionWorkflow(sessions, http)
        rsa_cert = generate_rsa_cert()
        zip_bytes = build_zip({"a.xml": b"<a/>"})

        session = await workflow.open_session(
            form_code=_form_code(),
            zip_bytes=zip_bytes,
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
        )
        assert session.session_reference_number == "SES-BATCH-1"

        resumed = workflow.resume_session(
            session.get_state(),
            zip_bytes=zip_bytes,
            access_token="token",
        )
        assert resumed.session_reference_number == "SES-BATCH-1"
        assert resumed.get_state().reference_number == "SES-BATCH-1"

        seen: list[int] = []
        await resumed.upload_parts(progress_callback=lambda ordinal: seen.append(ordinal))
        assert seen == [1]
        assert (await resumed.get_status()).status.code == 200
        assert (await resumed.list_invoices()).invoices == []
        assert (await resumed.list_failed_invoices()).invoices == []
        assert await resumed.get_upo("UPO-1") == b"<upo-session/>"
        await resumed.close()

        detached = AsyncBatchSessionHandle.from_state(
            session.get_state(),
            sessions_client=sessions,
            uploader=AsyncBatchUploadHelper(http),
            access_token="token",
        )
        with pytest.raises(ValueError):
            await detached.upload_parts()

        with pytest.raises(ValueError):
            workflow.resume_session(
                session.get_state(),
                zip_bytes=build_zip({"changed.xml": b"<x/>"}),
                access_token="token",
            )

    asyncio.run(_run())


def test_batch_upload_helper_progress_callback_runs_after_success() -> None:
    http = _RecordingHttp()
    helper = BatchUploadHelper(http)
    request = m.PartUploadRequest.from_dict(
        {
            "ordinalNumber": 1,
            "url": "https://upload/1",
            "method": "PUT",
            "headers": {},
        }
    )
    seen: list[int] = []

    helper.upload_parts(
        [request],
        [b"payload"],
        progress_callback=lambda ordinal: seen.append(ordinal),
    )

    assert seen == [1]
