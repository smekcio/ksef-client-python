"""A restored batch must decide retries using the original HTTP response."""

import base64
import json
from unittest.mock import Mock

import httpx
import pytest

from ksef_client import KsefClient, KsefClientOptions
from ksef_client import models as m
from ksef_client.batch_outcomes import BatchInvoiceManifest, prepare_invoice_batch
from ksef_client.exceptions import KsefDocumentValidationError
from ksef_client.services.sessions import BatchSessionHandle, BatchSessionState


def test_restored_batch_checks_the_wire_before_reporting_cancellation():
    manifest = prepare_invoice_batch({"invoice.xml": b"<invoice/>"}).manifest
    batch_file = m.BatchFileInfo(
        file_size=manifest.file_size, file_hash=manifest.file_hash, file_parts=[]
    )
    state = BatchSessionState(
        reference_number="batch-1",
        form_code=m.FormCode("FA (3)", "1-0E", "FA"),
        batch_file=batch_file,
        part_upload_requests=[],
        symmetric_key_base64=base64.b64encode(bytes(32)).decode(),
        iv_base64=base64.b64encode(bytes(16)).decode(),
    )
    saved = BatchInvoiceManifest.from_dict(manifest.to_dict())
    code = 550.5
    paths = []

    def respond(request):
        assert request.method == "GET"
        assert request.headers["Authorization"] == "Bearer test-token"
        paths.append(request.url.path)
        payload: dict[str, object]
        if request.url.path == "/v2/sessions/batch-1/invoices":
            payload = {
                "invoices": [
                    {
                        "status": {"code": code, "description": "cancelled"},
                        "ordinalNumber": 1,
                        "referenceNumber": "invoice-1",
                        "invoiceHash": manifest.invoices[0].invoice_hash,
                        "invoiceFileName": "invoice.xml",
                    }
                ],
                "continuationToken": "",
            }
        else:
            assert request.url.path == "/v2/sessions/batch-1"
            payload = {
                "status": {"code": 445, "description": "processed"},
                "dateCreated": "2026-10-01T12:00:00Z",
                "dateUpdated": "2026-10-01T12:01:00Z",
                "invoiceCount": 1,
                "successfulInvoiceCount": 0,
                "failedInvoiceCount": 1,
            }
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(payload).encode()))

    with KsefClient(KsefClientOptions(base_url="https://example.test/v2")) as api:
        api.http_client._client.close()
        api.http_client._client = httpx.Client(transport=httpx.MockTransport(respond))
        batch = BatchSessionHandle.from_state(
            state, sessions_client=api.sessions, uploader=Mock(), access_token="test-token"
        )
        with pytest.raises(KsefDocumentValidationError):
            batch.invoice_outcomes(saved)
        code = 550
        report = batch.invoice_outcomes(saved)
        assert report.complete and report.retry_candidates == saved.invoices
    assert len(paths) == 5
