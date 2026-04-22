from __future__ import annotations

from pathlib import Path

from ksef_client import models as m
from ksef_client.cli import app
from ksef_client.cli.sdk import session_ops
from ksef_client.cli.session_store import BatchSessionCheckpoint, load_checkpoint
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


def _form_code() -> m.FormCode:
    return m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")


def test_cli_online_session_resume_flow(runner, monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(session_ops.adapters, "get_tokens", lambda profile: ("acc", "ref"))

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Handle:
        def __init__(self, state: OnlineSessionState) -> None:
            self._state = state

        @property
        def session_reference_number(self) -> str:
            return self._state.reference_number

        def get_state(self) -> OnlineSessionState:
            return self._state

        def send_invoice(self, invoice_xml: bytes, *, access_token=None):
            _ = (invoice_xml, access_token)
            return {"referenceNumber": "INV-SMOKE-1"}

        def close(self, *, access_token=None):
            _ = access_token

    class _Workflow:
        def __init__(self, sessions) -> None:
            _ = sessions

        def open_session(self, **kwargs):
            _ = kwargs
            return _Handle(
                OnlineSessionState(
                    reference_number="SES-SMOKE-ONLINE",
                    form_code=_form_code(),
                    valid_until="2026-04-01T12:30:00Z",
                    symmetric_key_base64="AQID",
                    iv_base64="BAUG",
                )
            )

        def resume_session(self, state, *, access_token=None):
            _ = access_token
            return _Handle(state)

    monkeypatch.setattr(session_ops, "OnlineSessionWorkflow", _Workflow)
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=object(),
        ),
    )

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")

    assert runner.invoke(app, ["session", "online", "open", "--id", "smoke-online"]).exit_code == 0
    assert (
        runner.invoke(
            app,
            ["session", "online", "send", "--id", "smoke-online", "--invoice", str(invoice_path)],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["session", "online", "close", "--id", "smoke-online"]).exit_code == 0

    checkpoint = load_checkpoint("demo", "smoke-online")
    assert checkpoint.kind == "online"
    assert checkpoint.stage == "closed"


def test_cli_batch_session_resume_flow(runner, monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(session_ops.adapters, "get_tokens", lambda profile: ("acc", "ref"))

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _BatchSessionsApi:
        def close_batch_session(self, reference_number, access_token=None):
            _ = (reference_number, access_token)

    class _BatchHandle:
        def __init__(self, state: BatchSessionState) -> None:
            self._state = state

        @property
        def reference_number(self) -> str:
            return self._state.reference_number

        def get_state(self) -> BatchSessionState:
            return self._state

        def upload_parts(self, *, parallelism=1, skip_ordinals=None, progress_callback=None):
            _ = (parallelism, skip_ordinals)
            if progress_callback is not None:
                progress_callback(1)

        def close(self, *, access_token=None):
            _ = access_token

    batch_state = BatchSessionState(
        reference_number="SES-SMOKE-BATCH",
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

    class _BatchWorkflow:
        def __init__(self, sessions, http_client) -> None:
            _ = (sessions, http_client)

        def open_session(self, **kwargs):
            _ = kwargs
            return _BatchHandle(batch_state)

        def resume_session(self, state, *, zip_bytes, access_token=None):
            _ = (zip_bytes, access_token)
            return _BatchHandle(state)

    monkeypatch.setattr(session_ops, "BatchSessionWorkflow", _BatchWorkflow)
    monkeypatch.setattr(
        session_ops.adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(),
            sessions=_BatchSessionsApi(),
            http_client=object(),
        ),
    )

    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    (batch_dir / "1.xml").write_text("<a/>", encoding="utf-8")

    assert (
        runner.invoke(
            app,
            ["session", "batch", "open", "--id", "smoke-batch", "--dir", str(batch_dir)],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            ["session", "batch", "upload", "--id", "smoke-batch", "--parallelism", "1"],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["session", "batch", "close", "--id", "smoke-batch"]).exit_code == 0

    checkpoint = load_checkpoint("demo", "smoke-batch")
    assert isinstance(checkpoint, BatchSessionCheckpoint)
    assert checkpoint.kind == "batch"
    assert checkpoint.stage == "closed"
    assert checkpoint.uploaded_ordinals == [1]
