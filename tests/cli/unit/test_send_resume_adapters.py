from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from ksef_client import models as m
from ksef_client.cli.sdk import adapters
from ksef_client.cli.session_store import BatchSessionCheckpoint, load_checkpoint
from ksef_client.services.sessions import BatchSessionState, OnlineSessionState


class _FakeClient:
    def __init__(self, *, security=None, sessions=None, http_client=None) -> None:
        self.security = security
        self.sessions = sessions
        self.http_client = http_client

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)


def _form_code() -> m.FormCode:
    return m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")


def test_send_online_invoice_can_persist_session_checkpoint(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _SessionHandle:
        session_reference_number = "SES-ONLINE-1"
        encryption_data = SimpleNamespace(key=b"k", iv=b"i")

        def __init__(self) -> None:
            self.closed = 0

        def get_state(self):
            return OnlineSessionState(
                reference_number="SES-ONLINE-1",
                form_code=_form_code(),
                valid_until="2026-04-01T12:30:00Z",
                symmetric_key_base64="AQID",
                iv_base64="BAUG",
                upo_v43=True,
            )

        def send_invoice(self, invoice_xml: bytes, *, access_token=None):
            _ = (invoice_xml, access_token)
            return {"referenceNumber": "INV-ONLINE-1"}

        def close(self, *, access_token=None):
            _ = access_token
            self.closed += 1

    class _OnlineWorkflow:
        def __init__(self, sessions) -> None:
            _ = sessions
            self.handle = _SessionHandle()

        def open_session(self, **kwargs):
            _ = kwargs
            return self.handle

        def close_session(self, reference_number, access_token):
            _ = (reference_number, access_token)
            self.handle.close(access_token=access_token)

    workflow_holder: dict[str, _OnlineWorkflow] = {}

    def _workflow_factory(sessions):
        workflow = _OnlineWorkflow(sessions)
        workflow_holder["workflow"] = workflow
        return workflow

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _workflow_factory)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=SimpleNamespace(),
        ),
    )

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")

    result = adapters.send_online_invoice(
        profile="demo",
        base_url="https://example.invalid",
        invoice=str(invoice_path),
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        upo_v43=True,
        wait_status=False,
        wait_upo=False,
        poll_interval=1.0,
        max_attempts=1,
        save_upo=None,
        save_session="resume-online",
    )

    assert result["session_id"] == "resume-online"
    checkpoint = load_checkpoint("demo", "resume-online")
    assert checkpoint.kind == "online"
    assert checkpoint.stage == "closed"
    assert checkpoint.to_dict().get("access_token") is None
    assert workflow_holder["workflow"].handle.closed == 1


def test_send_batch_invoices_can_persist_session_checkpoint(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _BatchHandle:
        reference_number = "SES-BATCH-1"

        def __init__(self) -> None:
            self.closed = 0

        def get_state(self):
            return BatchSessionState(
                reference_number="SES-BATCH-1",
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

        def upload_parts(self, *, parallelism=1, skip_ordinals=None, progress_callback=None):
            _ = (parallelism, skip_ordinals)
            if progress_callback:
                progress_callback(1)
                progress_callback(2)

        def close(self, *, access_token=None):
            _ = access_token
            self.closed += 1

    class _BatchWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)
            self.handle = _BatchHandle()

        def open_session(self, **kwargs):
            _ = kwargs
            return self.handle

        def open_upload_and_close(self, **kwargs):
            _ = kwargs
            raise AssertionError("save_session path should not call open_upload_and_close")

    workflow_holder: dict[str, _BatchWorkflow] = {}

    def _workflow_factory(sessions, http_client):
        workflow = _BatchWorkflow(sessions, http_client)
        workflow_holder["workflow"] = workflow
        return workflow

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _workflow_factory)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=SimpleNamespace(),
            http_client=SimpleNamespace(),
        ),
    )

    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    (batch_dir / "1.xml").write_text("<a/>", encoding="utf-8")
    (batch_dir / "2.xml").write_text("<b/>", encoding="utf-8")

    result = adapters.send_batch_invoices(
        profile="demo",
        base_url="https://example.invalid",
        zip_path=None,
        directory=str(batch_dir),
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        parallelism=2,
        upo_v43=False,
        wait_status=False,
        wait_upo=False,
        poll_interval=1.0,
        max_attempts=1,
        save_upo=None,
        save_session="resume-batch",
    )

    assert result["session_id"] == "resume-batch"
    checkpoint = load_checkpoint("demo", "resume-batch")
    assert isinstance(checkpoint, BatchSessionCheckpoint)
    assert checkpoint.kind == "batch"
    assert checkpoint.stage == "closed"
    assert checkpoint.uploaded_ordinals == [1, 2]
    assert checkpoint.to_dict().get("access_token") is None
    assert workflow_holder["workflow"].handle.closed == 1


def test_send_online_invoice_closes_session_when_checkpoint_save_fails(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _SessionHandle:
        session_reference_number = "SES-ONLINE-1"
        encryption_data = SimpleNamespace(key=b"k", iv=b"i")

        def __init__(self) -> None:
            self.closed = 0

        def get_state(self):
            return OnlineSessionState(
                reference_number="SES-ONLINE-1",
                form_code=_form_code(),
                valid_until="2026-04-01T12:30:00Z",
                symmetric_key_base64="AQID",
                iv_base64="BAUG",
            )

        def close(self, *, access_token=None):
            _ = access_token
            self.closed += 1

    class _OnlineWorkflow:
        def __init__(self, sessions) -> None:
            _ = sessions
            self.handle = _SessionHandle()

        def open_session(self, **kwargs):
            _ = kwargs
            return self.handle

    workflow_holder: dict[str, _OnlineWorkflow] = {}

    def _workflow_factory(sessions):
        workflow = _OnlineWorkflow(sessions)
        workflow_holder["workflow"] = workflow
        return workflow

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _workflow_factory)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(
        adapters,
        "save_checkpoint",
        lambda checkpoint, overwrite=False: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")

    with pytest.raises(RuntimeError):
        adapters.send_online_invoice(
            profile="demo",
            base_url="https://example.invalid",
            invoice=str(invoice_path),
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            upo_v43=False,
            wait_status=False,
            wait_upo=False,
            poll_interval=1.0,
            max_attempts=1,
            save_upo=None,
            save_session="resume-online",
        )

    assert workflow_holder["workflow"].handle.closed == 1


def test_send_batch_invoices_handles_progress_checkpoint_edge_cases(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _BatchHandle:
        reference_number = "SES-BATCH-1"

        def __init__(self) -> None:
            self.closed = 0

        def get_state(self):
            return BatchSessionState(
                reference_number="SES-BATCH-1",
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

        def upload_parts(self, *, parallelism=1, skip_ordinals=None, progress_callback=None):
            _ = (parallelism, skip_ordinals)
            if progress_callback is not None:
                progress_callback(1)
                progress_callback(2)

        def close(self, *, access_token=None):
            _ = access_token
            self.closed += 1

    class _BatchWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)
            self.handle = _BatchHandle()

        def open_session(self, **kwargs):
            _ = kwargs
            return self.handle

    workflow_holder: dict[str, _BatchWorkflow] = {}
    saved: dict[str, BatchSessionCheckpoint] = {}

    def _workflow_factory(sessions, http_client):
        workflow = _BatchWorkflow(sessions, http_client)
        workflow_holder["workflow"] = workflow
        return workflow

    def _save_checkpoint(checkpoint, overwrite=False):
        _ = overwrite
        saved["checkpoint"] = checkpoint

    def _update_checkpoint(checkpoint, **changes):
        base = saved["checkpoint"] if checkpoint is None else checkpoint
        if changes.get("stage") == "uploading" and changes.get("uploaded_ordinals") == [1]:
            return None
        updated = replace(base, **changes)
        saved["checkpoint"] = updated
        return updated

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _workflow_factory)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=SimpleNamespace(),
            http_client=SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(adapters, "_load_batch_zip", lambda path: b"zip!")
    monkeypatch.setattr(
        adapters,
        "_build_batch_payload_source",
        lambda *, zip_path, directory, zip_bytes: adapters.BatchPayloadSource(
            kind="zip",
            path=str(zip_path),
            source_sha256_base64="hash",
            source_size=len(zip_bytes),
        ),
    )
    monkeypatch.setattr(adapters, "save_checkpoint", _save_checkpoint)
    monkeypatch.setattr(adapters, "update_checkpoint", _update_checkpoint)
    monkeypatch.setattr(
        adapters,
        "_wait_for_session_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Accepted"}},
    )
    monkeypatch.setattr(adapters, "_extract_status_fields", lambda payload: (200, "Accepted", []))
    monkeypatch.setattr(adapters, "_extract_upo_reference", lambda payload: "UPO-1")

    batch_zip = tmp_path / "batch.zip"
    batch_zip.write_bytes(b"zip!")

    result = adapters.send_batch_invoices(
        profile="demo",
        base_url="https://example.invalid",
        zip_path=str(batch_zip),
        directory=None,
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        parallelism=2,
        upo_v43=False,
        wait_status=True,
        wait_upo=False,
        poll_interval=1.0,
        max_attempts=1,
        save_upo=None,
        save_session="resume-batch",
    )

    assert result["status_code"] == 200
    assert saved["checkpoint"].last_upo_ref == "UPO-1"
    assert workflow_holder["workflow"].handle.closed == 1


def test_send_batch_invoices_closes_session_when_checkpoint_save_fails(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _BatchHandle:
        reference_number = "SES-BATCH-1"

        def __init__(self) -> None:
            self.closed = 0

        def get_state(self):
            return BatchSessionState(
                reference_number="SES-BATCH-1",
                form_code=_form_code(),
                batch_file=m.BatchFileInfo.from_dict(
                    {
                        "fileSize": 10,
                        "fileHash": "hash",
                        "fileParts": [{"ordinalNumber": 1, "fileSize": 10, "fileHash": "hash-1"}],
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

        def close(self, *, access_token=None):
            _ = access_token
            self.closed += 1

    class _BatchWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)
            self.handle = _BatchHandle()

        def open_session(self, **kwargs):
            _ = kwargs
            return self.handle

    workflow_holder: dict[str, _BatchWorkflow] = {}

    def _workflow_factory(sessions, http_client):
        workflow = _BatchWorkflow(sessions, http_client)
        workflow_holder["workflow"] = workflow
        return workflow

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _workflow_factory)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=SimpleNamespace(),
            http_client=SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(
        adapters,
        "_build_batch_payload_source",
        lambda *, zip_path, directory, zip_bytes: adapters.BatchPayloadSource(
            kind="zip",
            path=str(zip_path),
            source_sha256_base64="hash",
            source_size=len(zip_bytes),
        ),
    )
    monkeypatch.setattr(adapters, "_load_batch_zip", lambda path: b"zip!")
    monkeypatch.setattr(
        adapters,
        "save_checkpoint",
        lambda checkpoint, overwrite=False: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    batch_zip = tmp_path / "batch.zip"
    batch_zip.write_bytes(b"zip!")

    with pytest.raises(RuntimeError):
        adapters.send_batch_invoices(
            profile="demo",
            base_url="https://example.invalid",
            zip_path=str(batch_zip),
            directory=None,
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            parallelism=1,
            upo_v43=False,
            wait_status=False,
            wait_upo=False,
            poll_interval=1.0,
            max_attempts=1,
            save_upo=None,
            save_session="resume-batch",
        )

    assert workflow_holder["workflow"].handle.closed == 1
