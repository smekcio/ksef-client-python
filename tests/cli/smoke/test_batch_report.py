import base64
import json
from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from tests.test_batch_outcomes import FILES, A, remote, status

from ksef_client import models as m
from ksef_client.batch_outcomes import BatchInvoiceManifest, prepare_invoice_batch
from ksef_client.cli import app
from ksef_client.cli.auth.scope import login_scope, token_pair_digest
from ksef_client.cli.commands import _workflow
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.cli.sdk import adapters
from ksef_client.cli.session_store import (
    BatchPayloadSource,
    BatchSessionCheckpoint,
    _checkpoint_path,
    load_checkpoint,
    save_checkpoint,
)
from ksef_client.services.sessions import BatchSessionState
from ksef_client.services.workflows import BatchSessionWorkflow

BASE = "https://api-demo.ksef.mf.gov.pl"


def state(archive, compression):
    manifest = BatchInvoiceManifest.from_archive(archive, compression)
    return BatchSessionState(
        reference_number="batch-1",
        form_code=m.FormCode("FA (3)", "1-0E", "FA"),
        batch_file=m.BatchFileInfo(
            file_size=manifest.file_size,
            file_hash=manifest.file_hash,
            file_parts=[],
            compression_type=compression,
        ),
        part_upload_requests=[
            m.PartUploadRequest(
                headers={"X-Upload-Token": "test-upload-header"},
                method="PUT",
                ordinal_number=1,
                url="https://storage.example/part?signature=test-signed-url",
            )
        ],
        symmetric_key_base64=base64.b64encode(bytes(32)).decode(),
        iv_base64=base64.b64encode(bytes(16)).decode(),
    )


@pytest.fixture
def reports(runner, monkeypatch):
    tokens = ("demo-token", "demo-refresh")
    monkeypatch.delenv("KSEF_XADES_SELECTOR", raising=False)
    monkeypatch.setattr(_workflow, "get_tokens", lambda _: tokens)
    monkeypatch.setattr(
        _workflow,
        "get_cached_metadata",
        lambda _: {
            "login_scope": login_scope(BASE, "Nip", "123"),
            "token_pair_digest": token_pair_digest(*tokens),
        },
    )

    def invoke(*args, code=0, human=False):
        result = runner.invoke(app, [*([] if human else ["--json"]), *args])
        assert result.exit_code == code, (result.output, result.exception)
        if human:
            return result.output
        payload = json.loads(result.output)
        assert payload["ok"] is (code == 0)
        return payload["data"] if code == 0 else payload["errors"][0]

    return invoke


@pytest.mark.parametrize(
    "entry, compression",
    [
        ("send", m.CompressionType.ZIP),
        ("send", m.CompressionType.TARGZ),
        ("open", m.CompressionType.ZIP),
    ],
)
def test_report_from_normal_send_and_open_after_source_removed(
    reports, monkeypatch, tmp_path, entry, compression
):
    original = tmp_path / "input"
    original.mkdir()
    for name, xml in FILES.items():
        (original / name).write_bytes(xml)
    monkeypatch.setattr(adapters, "_require_access_token", lambda _: "demo-token")
    fake = SimpleNamespace(sessions=Mock(), http_client=Mock(), security=Mock())
    monkeypatch.setattr(adapters, "create_client", lambda *args, **kwargs: nullcontext(fake))
    monkeypatch.setattr(
        adapters,
        "_select_certificate",
        lambda *args: SimpleNamespace(certificate="cert", public_key_id="key"),
    )

    def open_batch(self, **kwargs):
        saved = state(kwargs.get("archive_bytes") or kwargs["zip_bytes"], compression)
        return SimpleNamespace(
            get_state=lambda: saved, close=Mock(), upload_parts=Mock(), reference_number="batch-1"
        )

    monkeypatch.setattr(BatchSessionWorkflow, "open_session", open_batch)
    if entry == "send":
        reports(
            "send",
            "batch",
            "--dir",
            str(original),
            "--archive-format",
            "zip" if compression is m.CompressionType.ZIP else "targz",
            "--save-session",
            "test-batch",
        )
    else:
        reports("session", "batch", "open", "--dir", str(original), "--id", "test-batch")
    saved = load_checkpoint("demo", "test-batch")
    assert isinstance(saved, BatchSessionCheckpoint) and saved.invoice_manifest is not None
    manifest = saved.invoice_manifest
    visible = reports("session", "show", "--id", "test-batch")["checkpoint"]
    assert visible["invoice_manifest"] == "<redacted>"
    parts = visible["session_state"]["part_upload_requests"]
    assert parts == [
        {"headers": "<redacted>", "method": "PUT", "ordinalNumber": 1, "url": "<redacted>"}
    ]
    assert "test-upload-header" not in json.dumps(visible) and "test-signed-url" not in json.dumps(
        visible
    )
    revealed = reports("session", "show", "--id", "test-batch", "--show-secrets")["checkpoint"]
    assert revealed["session_state"]["part_upload_requests"] == [
        saved.session_state.part_upload_requests[0].to_dict()
    ]
    assert not any(entry.file_name in json.dumps(visible) for entry in manifest.invoices)
    original.rename(tmp_path / "moved")
    calls = []
    is_final = False

    def respond(transport, req):
        assert req.method == "GET" and req.headers["authorization"] == "Bearer demo-token"
        calls.append(req.url.path)
        if req.url.path.endswith("/invoices"):
            rows = [
                remote(
                    it, i, code=code, ksef_number=A if code == 200 else None, name=it.file_name
                ).to_dict()
                for i, (it, code) in enumerate(
                    zip(manifest.invoices, (200, 450, 550), strict=True), start=1
                )
            ]
            assert req.url.params["pageSize"] == "10"
            token = req.headers.get("x-continuation-token")
            if token is None:
                data = {"invoices": rows[:1], "continuationToken": "page-two"}
            else:
                assert token == "page-two"
                data = {"invoices": rows[1:]}
        else:
            assert req.url.path.endswith("/sessions/batch-1")
            data = status(200 if is_final else 100).to_dict()
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(data).encode()))

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", respond)
    args = ["session", "batch", "report", "--id", "test-batch", "--page-size", "10"]
    assert "Partial report" in reports(*args, human=True)
    is_final = True
    result = reports(*args)
    assert result["complete"] and [row["disposition"] for row in result["invoices"]] == [
        "accepted",
        "rejected",
        "cancelled",
    ]
    assert result["retry_candidates"] == ["cancelled.xml"] and result["correction_candidates"] == [
        "bad.xml"
    ]
    assert all(
        secret not in str(result) for secret in ("storage.example", "demo-token", "symmetric_key")
    )
    assert "May retry" in reports(*args, human=True)
    assert calls.count("/v2/sessions/batch-1/invoices") == 4


@pytest.mark.parametrize(
    "compression,kind", [(m.CompressionType.ZIP, "zip"), (m.CompressionType.TARGZ, "tar_gz")]
)
def test_legacy_source_is_verified_before_api(reports, tmp_path, monkeypatch, compression, kind):
    prepared = prepare_invoice_batch(FILES, compression_type=compression)
    path = tmp_path / "original"
    path.write_bytes(prepared.archive_bytes)
    source = BatchPayloadSource(
        kind, str(path), prepared.manifest.file_hash, prepared.manifest.file_size
    )
    saved = BatchSessionCheckpoint(
        "old", "demo", BASE, "closed", state(prepared.archive_bytes, compression), source
    )
    save_checkpoint(saved)
    calls = []

    def pending(transport, req):
        calls.append(req.method)
        return httpx.Response(
            200, stream=httpx.ByteStream(json.dumps(status(100).to_dict()).encode())
        )

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", pending)
    args = ["session", "batch", "report", "--id", "old"]
    assert not reports(*args)["complete"]
    path.write_bytes(b"different")
    reports(*args, code=ExitCode.VALIDATION_ERROR)
    path.unlink()
    reports(*args, code=ExitCode.IO_ERROR)
    save_checkpoint(
        replace(saved, base_url="https://different.example", invoice_manifest=prepared.manifest)
    )
    reports(*args, code=ExitCode.VALIDATION_ERROR)
    checkpoint_file = _checkpoint_path("demo", "old")
    checkpoint_file.write_text(
        json.dumps({**saved.to_dict(), "profile": "other"}), encoding="utf-8"
    )
    assert "this profile" in reports(*args, code=ExitCode.VALIDATION_ERROR)["message"]
    assert calls == ["GET"]


def test_unindexable_checkpoint_returns_actionable_error(reports, tmp_path):
    from ksef_client.services.crypto import get_file_metadata
    from ksef_client.utils.zip_utils import build_zip

    data = build_zip({"note.txt": b"hello"})
    path = tmp_path / "unsupported.zip"
    path.write_bytes(data)
    metadata = get_file_metadata(data)
    prepared = prepare_invoice_batch(FILES)
    saved = BatchSessionCheckpoint(
        "old",
        "demo",
        BASE,
        "closed",
        state(prepared.archive_bytes, m.CompressionType.ZIP),
        BatchPayloadSource("zip", str(path), metadata.sha256_base64, metadata.file_size),
    )
    save_checkpoint(saved)
    assert (
        "cannot be indexed"
        in reports("session", "batch", "report", "--id", "old", code=ExitCode.VALIDATION_ERROR)[
            "message"
        ]
    )
