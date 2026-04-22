from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ksef_client import models as m
from ksef_client.cli import app
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.cli.sdk import adapters, session_ops
from ksef_client.cli.session_store import (
    BatchSessionCheckpoint,
    OnlineSessionCheckpoint,
    load_checkpoint,
)
from ksef_client.services.sessions import BatchSessionState, OnlineSessionState


class _FakeClient:
    def __init__(self, *, sessions=None, security=None, http_client=None) -> None:
        self.sessions = sessions
        self.security = security
        self.http_client = http_client

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)


class _Security:
    def get_public_key_certificates(self):
        return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]


class _BatchSessionsApi:
    def close_batch_session(self, reference_number, access_token=None):
        _ = (reference_number, access_token)


def _json_output(text: str) -> dict[str, Any]:
    return json.loads(text.strip().splitlines()[-1])


def _form_code() -> m.FormCode:
    return m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")


def _online_state(reference_number: str) -> OnlineSessionState:
    return OnlineSessionState(
        reference_number=reference_number,
        form_code=_form_code(),
        valid_until="2026-04-01T12:30:00Z",
        symmetric_key_base64="AQID",
        iv_base64="BAUG",
    )


def _batch_state(reference_number: str) -> BatchSessionState:
    return BatchSessionState(
        reference_number=reference_number,
        form_code=_form_code(),
        batch_file=m.BatchFileInfo.from_dict(
            {
                "fileSize": 10,
                "fileHash": "hash",
                "fileParts": [
                    {"ordinalNumber": 1, "fileSize": 5, "fileHash": "hash-1"},
                    {"ordinalNumber": 2, "fileSize": 5, "fileHash": "hash-2"},
                ],
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
            ),
            m.PartUploadRequest.from_dict(
                {
                    "ordinalNumber": 2,
                    "url": "https://upload/2",
                    "method": "PUT",
                    "headers": {},
                }
            ),
        ],
        symmetric_key_base64="AQID",
        iv_base64="BAUG",
    )


def test_cli_online_resume_uses_disk_checkpoint_after_logical_restart(
    runner, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=object(),
        ),
    )

    class _OpenHandle:
        def __init__(self, state: OnlineSessionState) -> None:
            self._state = state

        def get_state(self) -> OnlineSessionState:
            return self._state

    class _OpenWorkflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def open_session(self, **kwargs):
            _ = kwargs
            return _OpenHandle(_online_state("SES-RESTART-ONLINE"))

    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _OpenWorkflow)

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")

    open_result = runner.invoke(app, ["session", "online", "open", "--id", "restart-online"])
    assert open_result.exit_code == 0

    resumed_refs: list[str] = []

    class _ResumeHandle:
        def __init__(self, state: OnlineSessionState) -> None:
            self._state = state

        def send_invoice(self, invoice_xml: bytes, *, access_token=None):
            _ = (invoice_xml, access_token)
            resumed_refs.append(self._state.reference_number)
            return {"referenceNumber": "INV-RESTART-1"}

        def close(self, *, access_token=None):
            _ = access_token
            resumed_refs.append(self._state.reference_number)

    class _ResumeWorkflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def resume_session(self, state, *, access_token=None):
            _ = access_token
            return _ResumeHandle(state)

    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _ResumeWorkflow)

    send_result = runner.invoke(
        app,
        ["session", "online", "send", "--id", "restart-online", "--invoice", str(invoice_path)],
    )
    assert send_result.exit_code == 0

    close_result = runner.invoke(app, ["session", "online", "close", "--id", "restart-online"])
    assert close_result.exit_code == 0

    checkpoint = load_checkpoint("demo", "restart-online")
    assert isinstance(checkpoint, OnlineSessionCheckpoint)
    assert checkpoint.last_invoice_ref == "INV-RESTART-1"
    assert checkpoint.stage == "closed"
    assert resumed_refs == ["SES-RESTART-ONLINE", "SES-RESTART-ONLINE"]


def test_cli_batch_partial_upload_can_resume_after_logical_restart(
    runner, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=_BatchSessionsApi(),
            http_client=object(),
        ),
    )

    class _OpenHandle:
        def get_state(self) -> BatchSessionState:
            return _batch_state("SES-RESTART-BATCH")

    class _OpenWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def open_session(self, **kwargs):
            _ = kwargs
            return _OpenHandle()

    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _OpenWorkflow)

    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    (batch_dir / "1.xml").write_text("<a/>", encoding="utf-8")
    (batch_dir / "2.xml").write_text("<b/>", encoding="utf-8")

    open_result = runner.invoke(
        app,
        ["session", "batch", "open", "--id", "restart-batch", "--dir", str(batch_dir)],
    )
    assert open_result.exit_code == 0

    class _FirstUploadHandle:
        def upload_parts(self, *, parallelism=1, skip_ordinals=None, progress_callback=None):
            _ = parallelism
            if progress_callback is not None and 1 not in set(skip_ordinals or []):
                progress_callback(1)

    class _FirstUploadWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def resume_session(self, state, *, zip_bytes, access_token=None):
            _ = (state, zip_bytes, access_token)
            return _FirstUploadHandle()

    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _FirstUploadWorkflow)

    first_upload = runner.invoke(
        app,
        ["session", "batch", "upload", "--id", "restart-batch", "--parallelism", "1"],
    )
    assert first_upload.exit_code == 0

    checkpoint = load_checkpoint("demo", "restart-batch")
    assert isinstance(checkpoint, BatchSessionCheckpoint)
    assert checkpoint.uploaded_ordinals == [1]
    assert checkpoint.stage == "uploaded"

    seen_skip_ordinals: list[int] = []

    class _SecondUploadHandle:
        def upload_parts(self, *, parallelism=1, skip_ordinals=None, progress_callback=None):
            _ = parallelism
            seen_skip_ordinals[:] = sorted(skip_ordinals or [])
            if progress_callback is not None and 2 not in set(skip_ordinals or []):
                progress_callback(2)

    class _SecondUploadWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def resume_session(self, state, *, zip_bytes, access_token=None):
            _ = (state, zip_bytes, access_token)
            return _SecondUploadHandle()

    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _SecondUploadWorkflow)

    second_upload = runner.invoke(
        app,
        ["session", "batch", "upload", "--id", "restart-batch", "--parallelism", "1"],
    )
    assert second_upload.exit_code == 0

    close_result = runner.invoke(app, ["session", "batch", "close", "--id", "restart-batch"])
    assert close_result.exit_code == 0

    checkpoint = load_checkpoint("demo", "restart-batch")
    assert isinstance(checkpoint, BatchSessionCheckpoint)
    assert checkpoint.stage == "closed"
    assert checkpoint.uploaded_ordinals == [1, 2]
    assert seen_skip_ordinals == [1]


def test_cli_batch_resume_rejects_changed_payload_source(
    runner, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=_BatchSessionsApi(),
            http_client=object(),
        ),
    )

    class _OpenHandle:
        def get_state(self) -> BatchSessionState:
            return _batch_state("SES-MISMATCH-BATCH")

    class _OpenWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def open_session(self, **kwargs):
            _ = kwargs
            return _OpenHandle()

    class _UnexpectedResumeWorkflow(_OpenWorkflow):
        def resume_session(self, state, *, zip_bytes, access_token=None):
            raise AssertionError("payload mismatch should fail before resume_session")

    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _OpenWorkflow)

    batch_dir = tmp_path / "batch-mismatch"
    batch_dir.mkdir()
    invoice_path = batch_dir / "1.xml"
    invoice_path.write_text("<a/>", encoding="utf-8")

    open_result = runner.invoke(
        app,
        ["session", "batch", "open", "--id", "mismatch-batch", "--dir", str(batch_dir)],
    )
    assert open_result.exit_code == 0

    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _UnexpectedResumeWorkflow)
    invoice_path.write_text("<changed/>", encoding="utf-8")

    upload_result = runner.invoke(
        app,
        ["--json", "session", "batch", "upload", "--id", "mismatch-batch", "--parallelism", "1"],
    )

    assert upload_result.exit_code == int(ExitCode.VALIDATION_ERROR)
    payload = _json_output(upload_result.stdout)
    assert payload["errors"][0]["code"] == ExitCode.VALIDATION_ERROR.name
    assert "Batch payload source changed" in payload["errors"][0]["message"]


def test_cli_online_resume_requires_stored_token_after_open(
    runner, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=object(),
        ),
    )

    class _OpenHandle:
        def get_state(self) -> OnlineSessionState:
            return _online_state("SES-TOKEN-ONLINE")

    class _OpenWorkflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def open_session(self, **kwargs):
            _ = kwargs
            return _OpenHandle()

    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _OpenWorkflow)

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")

    open_result = runner.invoke(app, ["session", "online", "open", "--id", "token-online"])
    assert open_result.exit_code == 0

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: None)

    send_result = runner.invoke(
        app,
        [
            "--json",
            "session",
            "online",
            "send",
            "--id",
            "token-online",
            "--invoice",
            str(invoice_path),
        ],
    )

    assert send_result.exit_code == int(ExitCode.AUTH_ERROR)
    payload = _json_output(send_result.stdout)
    assert payload["errors"][0]["code"] == ExitCode.AUTH_ERROR.name


def test_cli_send_online_save_session_can_recover_via_session_commands(
    runner, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=object(),
        ),
    )

    class _FailingSendHandle:
        session_reference_number = "SES-SEND-ONLINE"

        def get_state(self) -> OnlineSessionState:
            return _online_state("SES-SEND-ONLINE")

        def send_invoice(self, invoice_xml: bytes, *, access_token=None):
            _ = (invoice_xml, access_token)
            raise RuntimeError("transient send failure")

        def close(self, *, access_token=None):
            _ = access_token

    class _FailingSendWorkflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def open_session(self, **kwargs):
            _ = kwargs
            return _FailingSendHandle()

    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _FailingSendWorkflow)

    invoice_path = tmp_path / "invoice-send.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")

    failed_send = runner.invoke(
        app,
        ["send", "online", "--invoice", str(invoice_path), "--save-session", "recover-online"],
    )
    assert failed_send.exit_code == int(ExitCode.CONFIG_ERROR)

    checkpoint = load_checkpoint("demo", "recover-online")
    assert isinstance(checkpoint, OnlineSessionCheckpoint)
    assert checkpoint.stage == "opened"

    class _RecoveredSendHandle:
        def __init__(self, state: OnlineSessionState) -> None:
            self._state = state

        def send_invoice(self, invoice_xml: bytes, *, access_token=None):
            _ = (invoice_xml, access_token)
            return {"referenceNumber": "INV-RECOVERED-ONLINE"}

        def close(self, *, access_token=None):
            _ = access_token

    class _RecoveredWorkflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def resume_session(self, state, *, access_token=None):
            _ = access_token
            return _RecoveredSendHandle(state)

    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _RecoveredWorkflow)

    resume_send = runner.invoke(
        app,
        ["session", "online", "send", "--id", "recover-online", "--invoice", str(invoice_path)],
    )
    assert resume_send.exit_code == 0

    close_result = runner.invoke(app, ["session", "online", "close", "--id", "recover-online"])
    assert close_result.exit_code == 0

    checkpoint = load_checkpoint("demo", "recover-online")
    assert isinstance(checkpoint, OnlineSessionCheckpoint)
    assert checkpoint.last_invoice_ref == "INV-RECOVERED-ONLINE"
    assert checkpoint.stage == "closed"


def test_cli_send_batch_save_session_can_recover_via_session_commands(
    runner, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=_BatchSessionsApi(),
            http_client=object(),
        ),
    )

    class _FailingBatchHandle:
        reference_number = "SES-SEND-BATCH"

        def get_state(self) -> BatchSessionState:
            return _batch_state("SES-SEND-BATCH")

        def upload_parts(self, *, parallelism=1, skip_ordinals=None, progress_callback=None):
            _ = (parallelism, skip_ordinals)
            if progress_callback is not None:
                progress_callback(1)
            raise RuntimeError("transient upload failure")

        def close(self, *, access_token=None):
            _ = access_token

    class _FailingBatchWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def open_session(self, **kwargs):
            _ = kwargs
            return _FailingBatchHandle()

    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _FailingBatchWorkflow)

    batch_dir = tmp_path / "batch-recover"
    batch_dir.mkdir()
    (batch_dir / "1.xml").write_text("<a/>", encoding="utf-8")
    (batch_dir / "2.xml").write_text("<b/>", encoding="utf-8")

    failed_send = runner.invoke(
        app,
        ["send", "batch", "--dir", str(batch_dir), "--save-session", "recover-batch"],
    )
    assert failed_send.exit_code == int(ExitCode.CONFIG_ERROR)

    checkpoint = load_checkpoint("demo", "recover-batch")
    assert isinstance(checkpoint, BatchSessionCheckpoint)
    assert checkpoint.stage == "uploading"
    assert checkpoint.uploaded_ordinals == [1]

    seen_skip_ordinals: list[int] = []

    class _RecoveredBatchHandle:
        def upload_parts(self, *, parallelism=1, skip_ordinals=None, progress_callback=None):
            _ = parallelism
            seen_skip_ordinals[:] = sorted(skip_ordinals or [])
            if progress_callback is not None and 2 not in set(skip_ordinals or []):
                progress_callback(2)

    class _RecoveredBatchWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def resume_session(self, state, *, zip_bytes, access_token=None):
            _ = (state, zip_bytes, access_token)
            return _RecoveredBatchHandle()

    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _RecoveredBatchWorkflow)

    resume_upload = runner.invoke(
        app,
        ["session", "batch", "upload", "--id", "recover-batch", "--parallelism", "1"],
    )
    assert resume_upload.exit_code == 0

    close_result = runner.invoke(app, ["session", "batch", "close", "--id", "recover-batch"])
    assert close_result.exit_code == 0

    checkpoint = load_checkpoint("demo", "recover-batch")
    assert isinstance(checkpoint, BatchSessionCheckpoint)
    assert checkpoint.stage == "closed"
    assert checkpoint.uploaded_ordinals == [1, 2]
    assert seen_skip_ordinals == [1]
