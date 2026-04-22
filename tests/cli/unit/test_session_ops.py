from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ksef_client import models as m
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.cli.sdk import session_ops
from ksef_client.cli.session_store import (
    BatchPayloadSource,
    BatchSessionCheckpoint,
    OnlineSessionCheckpoint,
)
from ksef_client.services.sessions import BatchSessionState, OnlineSessionState


def _form_code() -> m.FormCode:
    return m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")


def _online_checkpoint() -> OnlineSessionCheckpoint:
    return OnlineSessionCheckpoint(
        id="resume-online",
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        stage="opened",
        session_state=OnlineSessionState(
            reference_number="SES-ONLINE-1",
            form_code=_form_code(),
            valid_until="2026-04-01T12:30:00Z",
            symmetric_key_base64="AQID",
            iv_base64="BAUG",
        ),
    )


def _batch_checkpoint() -> BatchSessionCheckpoint:
    metadata = session_ops.get_file_metadata(b"zip!")
    return BatchSessionCheckpoint(
        id="resume-batch",
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        stage="opened",
        session_state=BatchSessionState(
            reference_number="SES-BATCH-1",
            form_code=_form_code(),
            batch_file=m.BatchFileInfo.from_dict(
                {
                    "fileSize": 4,
                    "fileHash": "hash",
                    "fileParts": [{"ordinalNumber": 1, "fileSize": 4, "fileHash": "hash-1"}],
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
        ),
        payload_source=BatchPayloadSource(
            kind="zip",
            path="C:/tmp/invoices.zip",
            source_sha256_base64=metadata.sha256_base64,
            source_size=metadata.file_size,
        ),
    )


class _FakeClient:
    def __init__(self, *, sessions=None, security=None, http_client=None) -> None:
        self.sessions = sessions
        self.security = security
        self.http_client = http_client

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)


def test_build_batch_payload_source_and_load_source_bytes(monkeypatch, tmp_path: Path) -> None:
    with pytest.raises(CliError) as exc:
        session_ops._build_batch_payload_source(zip_path=None, directory=None)
    assert exc.value.code == ExitCode.VALIDATION_ERROR

    zip_path = tmp_path / "payload.zip"
    zip_path.write_bytes(b"zip!")
    monkeypatch.setattr(
        session_ops.adapters, "_load_batch_zip", lambda path: Path(path).read_bytes()
    )
    zip_bytes, payload_source = session_ops._build_batch_payload_source(
        zip_path=str(zip_path),
        directory=None,
    )
    assert zip_bytes == b"zip!"
    assert payload_source.kind == "zip"

    loaded = session_ops._load_batch_source_bytes(payload_source)
    assert loaded == b"zip!"

    with pytest.raises(CliError) as mismatch_exc:
        session_ops._load_batch_source_bytes(
            replace(
                payload_source,
                source_sha256_base64="different",
            )
        )
    assert mismatch_exc.value.code == ExitCode.VALIDATION_ERROR


def test_session_ops_require_checkpoint_type_and_simple_commands(monkeypatch) -> None:
    batch_checkpoint = _batch_checkpoint()
    online_checkpoint = _online_checkpoint()

    monkeypatch.setattr(
        session_ops, "load_checkpoint", lambda profile, session_id: batch_checkpoint
    )
    with pytest.raises(CliError) as online_exc:
        session_ops._require_online_checkpoint("demo", "resume-batch")
    assert online_exc.value.code == ExitCode.VALIDATION_ERROR

    monkeypatch.setattr(
        session_ops, "load_checkpoint", lambda profile, session_id: online_checkpoint
    )
    with pytest.raises(CliError) as batch_exc:
        session_ops._require_batch_checkpoint("demo", "resume-online")
    assert batch_exc.value.code == ExitCode.VALIDATION_ERROR

    monkeypatch.setattr(
        session_ops, "list_checkpoints", lambda profile: [online_checkpoint, batch_checkpoint]
    )
    listed = session_ops.list_saved_sessions(profile="demo")
    assert listed["count"] == 2

    monkeypatch.setattr(
        session_ops, "load_checkpoint", lambda profile, session_id: batch_checkpoint
    )
    shown = session_ops.show_saved_session(profile="demo", session_id="resume-batch")
    assert shown["payload_source"]["kind"] == "zip"

    monkeypatch.setattr(
        session_ops,
        "export_checkpoint",
        lambda profile, session_id, out: out / "saved.json",
    )
    exported = session_ops.export_saved_session(
        profile="demo",
        session_id="resume-online",
        out="C:/tmp/export",
    )
    assert exported["path"].endswith("saved.json")

    monkeypatch.setattr(
        session_ops,
        "import_checkpoint",
        lambda profile, source_path, session_id=None: online_checkpoint,
    )
    imported = session_ops.import_saved_session(
        profile="demo",
        source_path="resume.json",
        session_id="resume-online",
    )
    assert imported["id"] == "resume-online"

    deleted: list[tuple[str, str]] = []
    monkeypatch.setattr(
        session_ops,
        "delete_checkpoint",
        lambda profile, session_id: deleted.append((profile, session_id)),
    )
    dropped = session_ops.drop_saved_session(profile="demo", session_id="resume-online")
    assert dropped["deleted"] is True
    assert deleted == [("demo", "resume-online")]

    monkeypatch.setattr(
        session_ops, "load_checkpoint", lambda profile, session_id: online_checkpoint
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "get_send_status",
        lambda **kwargs: {"session_ref": kwargs["session_ref"], "status_code": 200},
    )
    status = session_ops.get_saved_session_status(
        profile="demo",
        session_id="resume-online",
        invoice_ref="INV-1",
    )
    assert status["status_code"] == 200
    assert status["id"] == "resume-online"


def test_open_online_session_closes_handle_when_save_fails(monkeypatch) -> None:
    closed: list[str | None] = []

    class _Handle:
        def get_state(self) -> OnlineSessionState:
            return _online_checkpoint().session_state

        def close(self, *, access_token=None) -> None:
            closed.append(access_token)

    class _Workflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def open_session(self, **kwargs):
            _ = kwargs
            return _Handle()

    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")
    monkeypatch.setattr(session_ops.adapters, "_build_form_code", lambda *args: _form_code())
    monkeypatch.setattr(session_ops.adapters, "_select_certificate", lambda certs, usage: "CERT")
    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _Workflow)
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=SimpleNamespace(
                get_public_key_certificates=lambda: [{"usage": ["SymmetricKeyEncryption"]}]
            ),
            sessions=object(),
        ),
    )
    monkeypatch.setattr(
        session_ops,
        "save_checkpoint",
        lambda checkpoint, overwrite=False: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError):
        session_ops.open_online_session(
            profile="demo",
            base_url="https://example.invalid",
            session_id="resume-online",
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            upo_v43=True,
        )
    assert closed == ["token"]


def test_send_online_session_invoice_validates_and_waits(monkeypatch, tmp_path: Path) -> None:
    checkpoint = _online_checkpoint()
    monkeypatch.setattr(session_ops, "load_checkpoint", lambda profile, session_id: checkpoint)
    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")

    with pytest.raises(CliError) as exc:
        session_ops.send_online_session_invoice(
            profile="demo",
            session_id="resume-online",
            invoice="invoice.xml",
            wait_status=False,
            wait_upo=False,
            poll_interval=1.0,
            max_attempts=1,
            save_upo="upo.xml",
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR

    class _Handle:
        def send_invoice(self, invoice_xml: bytes, *, access_token=None):
            _ = (invoice_xml, access_token)
            return {}

    class _WorkflowNoRef:
        def __init__(self, sessions) -> None:
            _ = sessions

        def resume_session(self, state, *, access_token=None):
            _ = (state, access_token)
            return _Handle()

    monkeypatch.setattr(session_ops.adapters, "_load_invoice_xml", lambda invoice: b"<invoice/>")
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=object()),
    )
    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _WorkflowNoRef)
    monkeypatch.setattr(session_ops.adapters, "_extract_reference_number", lambda payload: "")

    with pytest.raises(CliError) as no_ref_exc:
        session_ops.send_online_session_invoice(
            profile="demo",
            session_id="resume-online",
            invoice="invoice.xml",
            wait_status=False,
            wait_upo=False,
            poll_interval=1.0,
            max_attempts=1,
            save_upo=None,
        )
    assert no_ref_exc.value.code == ExitCode.API_ERROR

    updated: list[OnlineSessionCheckpoint] = []
    validate_calls: list[tuple[float, int]] = []

    class _Workflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def resume_session(self, state, *, access_token=None):
            _ = (state, access_token)
            return SimpleNamespace(
                send_invoice=lambda invoice_xml, *, access_token=None: {"referenceNumber": "INV-1"}
            )

    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _Workflow)

    def _update_online_checkpoint(
        checkpoint: OnlineSessionCheckpoint,
        **changes: object,
    ) -> OnlineSessionCheckpoint:
        updated_checkpoint = replace(checkpoint, **cast(Any, changes))
        updated.append(updated_checkpoint)
        return updated_checkpoint

    monkeypatch.setattr(
        session_ops,
        "update_checkpoint",
        _update_online_checkpoint,
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "_validate_polling_options",
        lambda interval, attempts: validate_calls.append((interval, attempts)),
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "_wait_for_invoice_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Accepted"}},
    )
    monkeypatch.setattr(session_ops.adapters, "_extract_reference_number", lambda payload: "INV-1")
    monkeypatch.setattr(
        session_ops.adapters, "_extract_status_fields", lambda payload: (200, "Accepted", [])
    )
    monkeypatch.setattr(session_ops.adapters, "_extract_ksef_number", lambda payload: "KSEF-1")
    monkeypatch.setattr(session_ops.adapters, "_wait_for_invoice_upo", lambda **kwargs: b"<upo/>")
    monkeypatch.setattr(
        session_ops.adapters,
        "_resolve_output_path",
        lambda save_upo, default_filename: tmp_path / default_filename,
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "_save_bytes",
        lambda path, payload, overwrite=False: Path(path),
    )

    result = session_ops.send_online_session_invoice(
        profile="demo",
        session_id="resume-online",
        invoice="invoice.xml",
        wait_status=True,
        wait_upo=True,
        poll_interval=0.5,
        max_attempts=5,
        save_upo="upo.xml",
        save_upo_overwrite=True,
    )

    assert result["status_code"] == 200
    assert result["ksef_number"] == "KSEF-1"
    assert result["upo_path"].endswith("upo-SES-ONLINE-1-INV-1.xml")
    assert validate_calls == [(0.5, 5)]
    assert updated[-1].last_invoice_ref == "INV-1"


def test_send_online_session_invoice_wait_upo_without_saving_returns_empty_path(
    monkeypatch,
) -> None:
    checkpoint = _online_checkpoint()
    monkeypatch.setattr(session_ops, "load_checkpoint", lambda profile, session_id: checkpoint)
    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")
    monkeypatch.setattr(session_ops.adapters, "_load_invoice_xml", lambda invoice: b"<invoice/>")
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=object()),
    )
    monkeypatch.setattr(
        session_ops,
        "OnlineSessionWorkflow",
        lambda sessions: SimpleNamespace(
            resume_session=lambda state, *, access_token=None: SimpleNamespace(
                send_invoice=lambda invoice_xml, *, access_token=None: {"referenceNumber": "INV-1"}
            )
        ),
    )
    monkeypatch.setattr(
        session_ops, "update_checkpoint", lambda cp, **changes: replace(cp, **changes)
    )
    monkeypatch.setattr(session_ops.adapters, "_extract_reference_number", lambda payload: "INV-1")
    monkeypatch.setattr(
        session_ops.adapters,
        "_wait_for_invoice_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Accepted"}},
    )
    monkeypatch.setattr(
        session_ops.adapters, "_extract_status_fields", lambda payload: (200, "Accepted", [])
    )
    monkeypatch.setattr(session_ops.adapters, "_extract_ksef_number", lambda payload: "KSEF-1")
    monkeypatch.setattr(session_ops.adapters, "_wait_for_invoice_upo", lambda **kwargs: b"<upo/>")

    result = session_ops.send_online_session_invoice(
        profile="demo",
        session_id="resume-online",
        invoice="invoice.xml",
        wait_status=True,
        wait_upo=True,
        poll_interval=1.0,
        max_attempts=1,
        save_upo=None,
    )

    assert result["upo_path"] == ""


def test_open_batch_session_closes_handle_when_save_fails(monkeypatch) -> None:
    closed: list[str | None] = []

    class _Handle:
        def get_state(self) -> BatchSessionState:
            return _batch_checkpoint().session_state

        def close(self, *, access_token=None) -> None:
            closed.append(access_token)

    class _Workflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def open_session(self, **kwargs):
            _ = kwargs
            return _Handle()

    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")
    monkeypatch.setattr(session_ops.adapters, "_build_form_code", lambda *args: _form_code())
    monkeypatch.setattr(session_ops.adapters, "_select_certificate", lambda certs, usage: "CERT")
    monkeypatch.setattr(
        session_ops,
        "_build_batch_payload_source",
        lambda **kwargs: (b"zip!", _batch_checkpoint().payload_source),
    )
    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _Workflow)
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=SimpleNamespace(
                get_public_key_certificates=lambda: [{"usage": ["SymmetricKeyEncryption"]}]
            ),
            sessions=object(),
            http_client=object(),
        ),
    )
    monkeypatch.setattr(
        session_ops,
        "save_checkpoint",
        lambda checkpoint, overwrite=False: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError):
        session_ops.open_batch_session(
            profile="demo",
            base_url="https://example.invalid",
            session_id="resume-batch",
            zip_path="batch.zip",
            directory=None,
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            upo_v43=True,
        )
    assert closed == ["token"]


def test_upload_batch_session_validates_parallelism_and_updates_progress(monkeypatch) -> None:
    checkpoint = _batch_checkpoint()

    monkeypatch.setattr(session_ops, "load_checkpoint", lambda profile, session_id: checkpoint)
    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")
    with pytest.raises(CliError) as exc:
        session_ops.upload_batch_session(profile="demo", session_id="resume-batch", parallelism=0)
    assert exc.value.code == ExitCode.VALIDATION_ERROR

    updated: list[BatchSessionCheckpoint] = []

    class _Handle:
        def upload_parts(
            self, *, parallelism=1, skip_ordinals=None, progress_callback=None
        ) -> None:
            _ = (parallelism, skip_ordinals)
            if progress_callback is not None:
                progress_callback(1)

    class _Workflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def resume_session(self, state, *, zip_bytes, access_token=None):
            _ = (state, zip_bytes, access_token)
            return _Handle()

    monkeypatch.setattr(session_ops, "_load_batch_source_bytes", lambda source: b"zip!")
    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _Workflow)
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=object(), http_client=object()),
    )

    def _update_uploaded_checkpoint(
        checkpoint: BatchSessionCheckpoint,
        **changes: object,
    ) -> BatchSessionCheckpoint:
        updated_checkpoint = replace(checkpoint, **cast(Any, changes))
        updated.append(updated_checkpoint)
        return updated_checkpoint

    monkeypatch.setattr(
        session_ops,
        "update_checkpoint",
        _update_uploaded_checkpoint,
    )

    result = session_ops.upload_batch_session(
        profile="demo",
        session_id="resume-batch",
        parallelism=2,
    )

    assert result["uploaded_count"] == 1
    assert updated[-1].uploaded_ordinals == [1]


def test_close_batch_session_validates_and_waits(monkeypatch, tmp_path: Path) -> None:
    checkpoint = _batch_checkpoint()

    monkeypatch.setattr(session_ops, "load_checkpoint", lambda profile, session_id: checkpoint)
    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")
    with pytest.raises(CliError) as exc:
        session_ops.close_batch_session(
            profile="demo",
            session_id="resume-batch",
            wait_status=False,
            wait_upo=False,
            poll_interval=1.0,
            max_attempts=1,
            save_upo="upo.xml",
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR

    updated: list[BatchSessionCheckpoint] = []
    validate_calls: list[tuple[float, int]] = []
    close_calls: list[str | None] = []

    class _BatchHandleClass:
        @classmethod
        def from_state(cls, state, *, sessions_client, uploader, access_token=None):
            _ = (state, sessions_client, uploader)
            return SimpleNamespace(
                close=lambda *, access_token=None: close_calls.append(access_token)
            )

    monkeypatch.setattr(session_ops, "BatchSessionHandle", _BatchHandleClass)
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=object(),
            http_client=object(),
        ),
    )

    def _update_batch_checkpoint(
        checkpoint: BatchSessionCheckpoint,
        **changes: object,
    ) -> BatchSessionCheckpoint:
        updated_checkpoint = replace(checkpoint, **cast(Any, changes))
        updated.append(updated_checkpoint)
        return updated_checkpoint

    monkeypatch.setattr(
        session_ops,
        "update_checkpoint",
        _update_batch_checkpoint,
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "_validate_polling_options",
        lambda interval, attempts: validate_calls.append((interval, attempts)),
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "_wait_for_session_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Closed"}},
    )
    monkeypatch.setattr(
        session_ops.adapters, "_extract_status_fields", lambda payload: (200, "Closed", [])
    )
    monkeypatch.setattr(session_ops.adapters, "_extract_upo_reference", lambda payload: "UPO-1")
    monkeypatch.setattr(session_ops.adapters, "_wait_for_batch_upo", lambda **kwargs: b"<upo/>")
    monkeypatch.setattr(
        session_ops.adapters,
        "_resolve_output_path",
        lambda save_upo, default_filename: tmp_path / default_filename,
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "_save_bytes",
        lambda path, payload, overwrite=False: Path(path),
    )

    result = session_ops.close_batch_session(
        profile="demo",
        session_id="resume-batch",
        wait_status=True,
        wait_upo=True,
        poll_interval=0.5,
        max_attempts=5,
        save_upo="upo.xml",
        save_upo_overwrite=True,
    )

    assert result["status_code"] == 200
    assert result["upo_ref"] == "UPO-1"
    assert result["upo_path"].endswith("upo-SES-BATCH-1-UPO-1.xml")
    assert close_calls == ["token"]
    assert validate_calls == [(0.5, 5)]
    assert updated[-1].last_upo_ref == "UPO-1"


def test_close_batch_session_wait_upo_requires_reference(monkeypatch) -> None:
    checkpoint = _batch_checkpoint()
    updated: list[BatchSessionCheckpoint] = []
    monkeypatch.setattr(session_ops, "load_checkpoint", lambda profile, session_id: checkpoint)
    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")
    monkeypatch.setattr(
        session_ops,
        "BatchSessionHandle",
        type(
            "_BatchHandleClass",
            (),
            {
                "from_state": classmethod(
                    lambda cls, state, *, sessions_client, uploader, access_token=None: (
                        SimpleNamespace(close=lambda *, access_token=None: None)
                    )
                )
            },
        ),
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=object(), http_client=object()),
    )

    def _update_checkpoint(
        checkpoint: BatchSessionCheckpoint,
        **changes: object,
    ) -> BatchSessionCheckpoint:
        updated_checkpoint = replace(checkpoint, **cast(Any, changes))
        updated.append(updated_checkpoint)
        return updated_checkpoint

    monkeypatch.setattr(session_ops, "update_checkpoint", _update_checkpoint)
    monkeypatch.setattr(
        session_ops.adapters,
        "_wait_for_session_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Closed"}},
    )
    monkeypatch.setattr(
        session_ops.adapters, "_extract_status_fields", lambda payload: (200, "Closed", [])
    )
    monkeypatch.setattr(session_ops.adapters, "_extract_upo_reference", lambda payload: None)

    with pytest.raises(CliError) as exc:
        session_ops.close_batch_session(
            profile="demo",
            session_id="resume-batch",
            wait_status=True,
            wait_upo=True,
            poll_interval=1.0,
            max_attempts=1,
            save_upo=None,
        )
    assert exc.value.code == ExitCode.RETRY_EXHAUSTED


def test_close_batch_session_wait_upo_without_saving_returns_empty_path(monkeypatch) -> None:
    checkpoint = _batch_checkpoint()
    updated: list[BatchSessionCheckpoint] = []
    monkeypatch.setattr(session_ops, "load_checkpoint", lambda profile, session_id: checkpoint)
    monkeypatch.setattr(session_ops.adapters, "_require_access_token", lambda profile: "token")
    monkeypatch.setattr(
        session_ops,
        "BatchSessionHandle",
        type(
            "_BatchHandleClass",
            (),
            {
                "from_state": classmethod(
                    lambda cls, state, *, sessions_client, uploader, access_token=None: (
                        SimpleNamespace(close=lambda *, access_token=None: None)
                    )
                )
            },
        ),
    )
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=object(), http_client=object()),
    )

    def _update_checkpoint(
        checkpoint: BatchSessionCheckpoint,
        **changes: object,
    ) -> BatchSessionCheckpoint:
        updated_checkpoint = replace(checkpoint, **cast(Any, changes))
        updated.append(updated_checkpoint)
        return updated_checkpoint

    monkeypatch.setattr(session_ops, "update_checkpoint", _update_checkpoint)
    monkeypatch.setattr(
        session_ops.adapters,
        "_wait_for_session_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Closed"}},
    )
    monkeypatch.setattr(
        session_ops.adapters, "_extract_status_fields", lambda payload: (200, "Closed", [])
    )
    monkeypatch.setattr(session_ops.adapters, "_extract_upo_reference", lambda payload: "UPO-1")
    monkeypatch.setattr(session_ops.adapters, "_wait_for_batch_upo", lambda **kwargs: b"<upo/>")

    result = session_ops.close_batch_session(
        profile="demo",
        session_id="resume-batch",
        wait_status=True,
        wait_upo=True,
        poll_interval=1.0,
        max_attempts=1,
        save_upo=None,
    )

    assert result["upo_path"] == ""
