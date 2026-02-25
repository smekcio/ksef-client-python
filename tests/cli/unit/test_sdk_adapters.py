from __future__ import annotations

from types import SimpleNamespace

import pytest

from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.cli.sdk import adapters
from ksef_client.exceptions import KsefHttpError


class _FakeClient:
    def __init__(
        self,
        *,
        invoices=None,
        sessions=None,
        security=None,
        lighthouse=None,
        http_client=None,
    ) -> None:
        self.invoices = invoices
        self.sessions = sessions
        self.security = security
        self.lighthouse = lighthouse
        self.http_client = http_client

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)


def test_list_invoices_success(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class _Invoices:
        def query_invoice_metadata(self, payload, **kwargs):
            seen["payload"] = payload
            seen.update(kwargs)
            return {"invoices": [{"ksefReferenceNumber": "KSEF-1"}], "continuationToken": "ct"}

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=_Invoices()),
    )

    result = adapters.list_invoices(
        profile="demo",
        base_url="https://example.invalid",
        date_from="2026-01-01",
        date_to="2026-01-31",
        subject_type="Subject1",
        date_type="Issue",
        page_size=10,
        page_offset=0,
        sort_order="Desc",
    )

    assert result["count"] == 1
    assert result["continuation_token"] == "ct"
    assert seen["page_size"] == 10
    assert seen["sort_order"] == "Desc"
    payload = seen["payload"]
    assert isinstance(payload, dict)
    assert payload["subjectType"] == "Subject1"


def test_list_invoices_requires_token(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: None)
    with pytest.raises(CliError) as exc:
        adapters.list_invoices(
            profile="demo",
            base_url="https://example.invalid",
            date_from=None,
            date_to=None,
            subject_type="Subject1",
            date_type="Issue",
            page_size=10,
            page_offset=0,
            sort_order="Desc",
        )
    assert exc.value.code == ExitCode.AUTH_ERROR


def test_list_invoices_rejects_invalid_dates(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=SimpleNamespace()),
    )

    with pytest.raises(CliError) as exc:
        adapters.list_invoices(
            profile="demo",
            base_url="https://example.invalid",
            date_from="2026-13-01",
            date_to=None,
            subject_type="Subject1",
            date_type="Issue",
            page_size=10,
            page_offset=0,
            sort_order="Desc",
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_list_invoices_rejects_reverse_date_range(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=SimpleNamespace()),
    )

    with pytest.raises(CliError) as exc:
        adapters.list_invoices(
            profile="demo",
            base_url="https://example.invalid",
            date_from="2026-02-01",
            date_to="2026-01-01",
            subject_type="Subject1",
            date_type="Issue",
            page_size=10,
            page_offset=0,
            sort_order="Desc",
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_get_lighthouse_status_success(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class _Lighthouse:
        def get_status(self):
            message = SimpleNamespace(
                to_dict=lambda: {
                    "id": "m-1",
                    "eventId": 1,
                    "category": "MAINTENANCE",
                    "type": "MAINTENANCE_ANNOUNCEMENT",
                    "title": "Planned",
                    "text": "Window",
                    "start": "2026-03-15T01:00:00Z",
                    "end": "2026-03-15T06:00:00Z",
                    "version": 1,
                    "published": "2026-03-10T12:00:00Z",
                }
            )
            return SimpleNamespace(status=SimpleNamespace(value="MAINTENANCE"), messages=[message])

    def _fake_create_client(base_url, access_token=None, base_lighthouse_url=None):
        seen["base_url"] = base_url
        seen["access_token"] = access_token
        seen["base_lighthouse_url"] = base_lighthouse_url
        return _FakeClient(lighthouse=_Lighthouse())

    monkeypatch.setattr(adapters, "create_client", _fake_create_client)

    result = adapters.get_lighthouse_status(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        lighthouse_base_url="https://api-latarnia-test.ksef.mf.gov.pl",
    )

    assert seen["base_url"] == "https://api-demo.ksef.mf.gov.pl"
    assert seen["base_lighthouse_url"] == "https://api-latarnia-test.ksef.mf.gov.pl"
    assert seen["access_token"] is None
    assert result["status"] == "MAINTENANCE"
    assert len(result["messages"]) == 1


def test_get_lighthouse_messages_success(monkeypatch) -> None:
    class _Lighthouse:
        def get_messages(self):
            return [
                SimpleNamespace(
                    to_dict=lambda: {
                        "id": "m-1",
                        "eventId": 1,
                        "category": "FAILURE",
                        "type": "FAILURE_START",
                        "title": "Failure",
                        "text": "Down",
                        "start": "2026-05-12T10:00:00Z",
                        "end": None,
                        "version": 1,
                        "published": "2026-05-12T10:01:00Z",
                    }
                )
            ]

    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None, base_lighthouse_url=None: _FakeClient(
            lighthouse=_Lighthouse()
        ),
    )

    result = adapters.get_lighthouse_messages(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        lighthouse_base_url=None,
    )

    assert result["count"] == 1
    assert result["items"][0]["id"] == "m-1"


def test_download_invoice_xml_success(monkeypatch, tmp_path) -> None:
    class _Invoices:
        def get_invoice(self, ksef_number, access_token):
            _ = (ksef_number, access_token)
            return SimpleNamespace(content="<faktura/>", sha256_base64="hash")

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=_Invoices()),
    )

    result = adapters.download_invoice(
        profile="demo",
        base_url="https://example.invalid",
        ksef_number="KSEF-1",
        out=str(tmp_path / "invoice.xml"),
        as_format="xml",
        overwrite=False,
    )

    assert result["ksef_number"] == "KSEF-1"
    assert (tmp_path / "invoice.xml").read_text(encoding="utf-8") == "<faktura/>"


def test_download_invoice_bytes_uses_default_filename(monkeypatch, tmp_path) -> None:
    class _Invoices:
        def get_invoice_bytes(self, ksef_number, access_token):
            _ = (ksef_number, access_token)
            return SimpleNamespace(content=b"\x01\x02", sha256_base64="hashb")

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=_Invoices()),
    )

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = adapters.download_invoice(
        profile="demo",
        base_url="https://example.invalid",
        ksef_number="KSEF-2",
        out=str(out_dir),
        as_format="bytes",
        overwrite=False,
    )

    target = out_dir / "KSEF-2.bin"
    assert target.read_bytes() == b"\x01\x02"
    assert result["path"] == str(target)


def test_download_invoice_respects_overwrite(monkeypatch, tmp_path) -> None:
    class _Invoices:
        def get_invoice(self, ksef_number, access_token):
            _ = (ksef_number, access_token)
            return SimpleNamespace(content="<xml/>", sha256_base64="")

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=_Invoices()),
    )

    target = tmp_path / "invoice.xml"
    target.write_text("old", encoding="utf-8")

    with pytest.raises(CliError) as exc:
        adapters.download_invoice(
            profile="demo",
            base_url="https://example.invalid",
            ksef_number="KSEF-3",
            out=str(target),
            as_format="xml",
            overwrite=False,
        )
    assert exc.value.code == ExitCode.IO_ERROR


def test_get_upo_requires_single_identifier(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))

    with pytest.raises(CliError) as exc:
        adapters.get_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-1",
            invoice_ref="INV-1",
            ksef_number="KSEF-1",
            upo_ref=None,
            out="upo.xml",
            overwrite=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_get_upo_by_invoice_ref_success(monkeypatch, tmp_path) -> None:
    class _Sessions:
        def get_session_invoice_upo_by_ref(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return b"<upo/>"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )

    result = adapters.get_upo(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-1",
        invoice_ref="INV-1",
        ksef_number=None,
        upo_ref=None,
        out=str(tmp_path / "upo.xml"),
        overwrite=False,
    )

    assert result["session_ref"] == "SES-1"
    assert (tmp_path / "upo.xml").read_bytes() == b"<upo/>"


def test_wait_for_upo_invoice_ref_success(monkeypatch, tmp_path) -> None:
    class _Sessions:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return {"status": {"code": 200}}

        def get_session_invoice_upo_by_ref(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return b"<upo-online/>"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    result = adapters.wait_for_upo(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-1",
        invoice_ref="INV-1",
        upo_ref=None,
        batch_auto=False,
        poll_interval=0.01,
        max_attempts=2,
        out=str(tmp_path / "upo-online.xml"),
        overwrite=False,
    )

    assert result["invoice_ref"] == "INV-1"
    assert (tmp_path / "upo-online.xml").read_bytes() == b"<upo-online/>"


def test_wait_for_upo_invoice_ref_retries_transient_status_http(monkeypatch, tmp_path) -> None:
    class _Sessions:
        def __init__(self) -> None:
            self._status_calls = 0

        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            self._status_calls += 1
            if self._status_calls == 1:
                raise KsefHttpError(status_code=425, message="Not ready")
            return {"status": {"code": 200}}

        def get_session_invoice_upo_by_ref(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return b"<upo-online-transient/>"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    result = adapters.wait_for_upo(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-1",
        invoice_ref="INV-1",
        upo_ref=None,
        batch_auto=False,
        poll_interval=0.01,
        max_attempts=3,
        out=str(tmp_path / "upo-online-transient.xml"),
        overwrite=False,
    )

    assert result["invoice_ref"] == "INV-1"
    assert (tmp_path / "upo-online-transient.xml").read_bytes() == b"<upo-online-transient/>"


def test_wait_for_upo_batch_auto_success(monkeypatch, tmp_path) -> None:
    class _Sessions:
        def __init__(self) -> None:
            self._calls = 0

        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            self._calls += 1
            if self._calls == 1:
                return {"upoReferenceNumber": "UPO-1"}
            return {}

        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            return b"<upo-batch/>"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    result = adapters.wait_for_upo(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-2",
        invoice_ref=None,
        upo_ref=None,
        batch_auto=True,
        poll_interval=0.01,
        max_attempts=3,
        out=str(tmp_path / "upo-batch.xml"),
        overwrite=False,
    )

    assert result["upo_ref"] == "UPO-1"
    assert (tmp_path / "upo-batch.xml").read_bytes() == b"<upo-batch/>"


def test_wait_for_upo_retries_transient_and_times_out(monkeypatch) -> None:
    class _Sessions:
        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            raise KsefHttpError(status_code=409, message="Not ready")

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    with pytest.raises(CliError) as exc:
        adapters.wait_for_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-3",
            invoice_ref=None,
            upo_ref="UPO-3",
            batch_auto=False,
            poll_interval=0.01,
            max_attempts=2,
            out=None,
            overwrite=False,
        )
    assert exc.value.code == ExitCode.RETRY_EXHAUSTED


def test_wait_for_upo_rejects_invalid_polling_options(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))

    with pytest.raises(CliError) as exc_interval:
        adapters.wait_for_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-4",
            invoice_ref=None,
            upo_ref="UPO-4",
            batch_auto=False,
            poll_interval=0.0,
            max_attempts=1,
            out=None,
            overwrite=False,
        )
    assert exc_interval.value.code == ExitCode.VALIDATION_ERROR

    with pytest.raises(CliError) as exc_attempts:
        adapters.wait_for_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-4",
            invoice_ref=None,
            upo_ref="UPO-4",
            batch_auto=False,
            poll_interval=1.0,
            max_attempts=0,
            out=None,
            overwrite=False,
        )
    assert exc_attempts.value.code == ExitCode.VALIDATION_ERROR


def test_send_online_invoice_success_with_wait_and_upo(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return {"status": {"code": 200, "description": "Accepted"}, "ksefNumber": "KSEF-1"}

        def get_session_invoice_upo_by_ref(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return b"<upo-online/>"

    class _OnlineWorkflow:
        def __init__(self, sessions):
            _ = sessions
            self.closed_refs: list[str] = []

        def open_session(self, *, form_code, public_certificate, access_token, upo_v43=False):
            _ = (form_code, public_certificate, access_token, upo_v43)
            return SimpleNamespace(
                session_reference_number="SES-ONLINE-1",
                encryption_data=SimpleNamespace(key=b"k", iv=b"i"),
            )

        def send_invoice(self, **kwargs):
            _ = kwargs
            return {"referenceNumber": "INV-ONLINE-1"}

        def close_session(self, reference_number, access_token):
            _ = access_token
            self.closed_refs.append(reference_number)

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
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions(), security=_Security()),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")
    upo_path = tmp_path / "upo.xml"

    result = adapters.send_online_invoice(
        profile="demo",
        base_url="https://example.invalid",
        invoice=str(invoice_path),
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        upo_v43=True,
        wait_status=True,
        wait_upo=True,
        poll_interval=0.01,
        max_attempts=2,
        save_upo=str(upo_path),
    )

    assert result["session_ref"] == "SES-ONLINE-1"
    assert result["invoice_ref"] == "INV-ONLINE-1"
    assert result["ksef_number"] == "KSEF-1"
    assert result["upo_bytes"] == len(b"<upo-online/>")
    assert upo_path.read_bytes() == b"<upo-online/>"
    assert workflow_holder["workflow"].closed_refs == ["SES-ONLINE-1"]


def test_send_online_invoice_save_upo_without_extension_is_treated_as_file(
    monkeypatch, tmp_path
) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return {"status": {"code": 200, "description": "Accepted"}, "ksefNumber": "KSEF-1"}

        def get_session_invoice_upo_by_ref(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return b"<upo-online/>"

    class _OnlineWorkflow:
        def __init__(self, sessions):
            _ = sessions

        def open_session(self, *, form_code, public_certificate, access_token, upo_v43=False):
            _ = (form_code, public_certificate, access_token, upo_v43)
            return SimpleNamespace(
                session_reference_number="SES-ONLINE-2",
                encryption_data=SimpleNamespace(key=b"k", iv=b"i"),
            )

        def send_invoice(self, **kwargs):
            _ = kwargs
            return {"referenceNumber": "INV-ONLINE-2"}

        def close_session(self, reference_number, access_token):
            _ = (reference_number, access_token)

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _OnlineWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions(), security=_Security()),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")
    upo_path = tmp_path / "upo-no-ext"

    result = adapters.send_online_invoice(
        profile="demo",
        base_url="https://example.invalid",
        invoice=str(invoice_path),
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        upo_v43=False,
        wait_status=True,
        wait_upo=True,
        poll_interval=0.01,
        max_attempts=2,
        save_upo=str(upo_path),
    )

    assert result["upo_path"] == str(upo_path)
    assert upo_path.read_bytes() == b"<upo-online/>"


def test_send_online_invoice_save_upo_overwrite_support(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _OnlineWorkflow:
        def __init__(self, sessions):
            _ = sessions

        def open_session(self, *, form_code, public_certificate, access_token, upo_v43=False):
            _ = (form_code, public_certificate, access_token, upo_v43)
            return SimpleNamespace(
                session_reference_number="SES-ONLINE-OVERWRITE",
                encryption_data=SimpleNamespace(key=b"k", iv=b"i"),
            )

        def send_invoice(self, **kwargs):
            _ = kwargs
            return {"referenceNumber": "INV-ONLINE-OVERWRITE"}

        def close_session(self, reference_number, access_token):
            _ = (reference_number, access_token)

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _OnlineWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=SimpleNamespace(),
            security=_Security(),
        ),
    )
    monkeypatch.setattr(
        adapters,
        "_wait_for_invoice_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Accepted"}},
    )
    monkeypatch.setattr(adapters, "_wait_for_invoice_upo", lambda **kwargs: b"<upo-new/>")

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")
    upo_path = tmp_path / "upo-overwrite.xml"
    upo_path.write_bytes(b"<old/>")

    with pytest.raises(CliError) as no_overwrite:
        adapters.send_online_invoice(
            profile="demo",
            base_url="https://example.invalid",
            invoice=str(invoice_path),
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            upo_v43=False,
            wait_status=True,
            wait_upo=True,
            poll_interval=0.01,
            max_attempts=1,
            save_upo=str(upo_path),
        )
    assert no_overwrite.value.code == ExitCode.IO_ERROR

    result = adapters.send_online_invoice(
        profile="demo",
        base_url="https://example.invalid",
        invoice=str(invoice_path),
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        upo_v43=False,
        wait_status=True,
        wait_upo=True,
        poll_interval=0.01,
        max_attempts=1,
        save_upo=str(upo_path),
        save_upo_overwrite=True,
    )

    assert result["upo_path"] == str(upo_path)
    assert upo_path.read_bytes() == b"<upo-new/>"


def test_send_online_invoice_validates_save_upo_dependency(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")

    with pytest.raises(CliError) as exc:
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
            save_upo=str(tmp_path / "upo.xml"),
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_send_online_invoice_requires_certificate(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["KsefTokenEncryption"], "certificate": "CERT"}]

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            security=_Security(), sessions=SimpleNamespace()
        ),
    )
    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")

    with pytest.raises(CliError) as exc:
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
        )
    assert exc.value.code == ExitCode.API_ERROR


def test_send_batch_invoices_success_with_dir(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _BatchWorkflow:
        def __init__(self, sessions, http_client):
            _ = (sessions, http_client)
            self.calls: list[dict[str, object]] = []

        def open_upload_and_close(self, **kwargs):
            self.calls.append(kwargs)
            return "SES-BATCH-1"

    workflow_holder: dict[str, _BatchWorkflow] = {}

    def _batch_factory(sessions, http_client):
        workflow = _BatchWorkflow(sessions, http_client)
        workflow_holder["workflow"] = workflow
        return workflow

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _batch_factory)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=SimpleNamespace(),
            security=_Security(),
            http_client=SimpleNamespace(),
        ),
    )

    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    (batch_dir / "a.xml").write_text("<a/>", encoding="utf-8")

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
    )

    assert result["session_ref"] == "SES-BATCH-1"
    call = workflow_holder["workflow"].calls[0]
    assert call["parallelism"] == 2
    assert isinstance(call["zip_bytes"], bytes)
    assert len(call["zip_bytes"]) > 0


def test_send_batch_invoices_validates_input_source(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))

    with pytest.raises(CliError) as exc:
        adapters.send_batch_invoices(
            profile="demo",
            base_url="https://example.invalid",
            zip_path="a.zip",
            directory="dir",
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
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_send_batch_invoices_wait_upo_requires_upo_ref(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            return {"status": {"code": 200, "description": "Done"}}

    class _BatchWorkflow:
        def __init__(self, sessions, http_client):
            _ = (sessions, http_client)

        def open_upload_and_close(self, **kwargs):
            _ = kwargs
            return "SES-BATCH-2"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _BatchWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=_Sessions(),
            security=_Security(),
            http_client=SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)
    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    with pytest.raises(CliError) as exc:
        adapters.send_batch_invoices(
            profile="demo",
            base_url="https://example.invalid",
            zip_path=str(zip_path),
            directory=None,
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            parallelism=1,
            upo_v43=False,
            wait_status=True,
            wait_upo=True,
            poll_interval=0.01,
            max_attempts=1,
            save_upo=None,
        )
    assert exc.value.code == ExitCode.RETRY_EXHAUSTED


def test_send_batch_invoices_wait_upo_success(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        def __init__(self) -> None:
            self._upo_calls = 0

        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            return {"status": {"code": 200, "description": "Done"}, "upoReferenceNumber": "UPO-B-1"}

        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            self._upo_calls += 1
            if self._upo_calls == 1:
                raise KsefHttpError(status_code=409, message="Not ready")
            return b"<upo-batch/>"

    class _BatchWorkflow:
        def __init__(self, sessions, http_client):
            _ = (sessions, http_client)

        def open_upload_and_close(self, **kwargs):
            _ = kwargs
            return "SES-BATCH-3"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _BatchWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=_Sessions(),
            security=_Security(),
            http_client=SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x03\x04")
    save_path = tmp_path / "upo-batch.xml"

    result = adapters.send_batch_invoices(
        profile="demo",
        base_url="https://example.invalid",
        zip_path=str(zip_path),
        directory=None,
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        parallelism=1,
        upo_v43=False,
        wait_status=True,
        wait_upo=True,
        poll_interval=0.01,
        max_attempts=3,
        save_upo=str(save_path),
    )

    assert result["session_ref"] == "SES-BATCH-3"
    assert result["upo_ref"] == "UPO-B-1"
    assert save_path.read_bytes() == b"<upo-batch/>"


def test_send_batch_invoices_save_upo_overwrite_support(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _BatchWorkflow:
        def __init__(self, sessions, http_client):
            _ = (sessions, http_client)

        def open_upload_and_close(self, **kwargs):
            _ = kwargs
            return "SES-BATCH-OVERWRITE"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _BatchWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=SimpleNamespace(),
            security=_Security(),
            http_client=SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(
        adapters,
        "_wait_for_session_status",
        lambda **kwargs: {
            "status": {"code": 200, "description": "Done"},
            "upoReferenceNumber": "UPO-BATCH-OVERWRITE",
        },
    )
    monkeypatch.setattr(adapters, "_wait_for_batch_upo", lambda **kwargs: b"<upo-batch-new/>")

    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x03\x04")
    save_path = tmp_path / "upo-batch-overwrite.xml"
    save_path.write_bytes(b"<old/>")

    with pytest.raises(CliError) as no_overwrite:
        adapters.send_batch_invoices(
            profile="demo",
            base_url="https://example.invalid",
            zip_path=str(zip_path),
            directory=None,
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            parallelism=1,
            upo_v43=False,
            wait_status=True,
            wait_upo=True,
            poll_interval=0.01,
            max_attempts=1,
            save_upo=str(save_path),
        )
    assert no_overwrite.value.code == ExitCode.IO_ERROR

    result = adapters.send_batch_invoices(
        profile="demo",
        base_url="https://example.invalid",
        zip_path=str(zip_path),
        directory=None,
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        parallelism=1,
        upo_v43=False,
        wait_status=True,
        wait_upo=True,
        poll_interval=0.01,
        max_attempts=1,
        save_upo=str(save_path),
        save_upo_overwrite=True,
    )

    assert result["upo_path"] == str(save_path)
    assert save_path.read_bytes() == b"<upo-batch-new/>"


def test_get_send_status_online_and_batch(monkeypatch) -> None:
    class _Sessions:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return {"status": {"code": 200, "description": "Accepted"}, "ksefNumber": "KSEF-9"}

        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            return {
                "status": {"code": 100, "description": "Processing"},
                "upoReferenceNumber": "UPO-9",
            }

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )

    online = adapters.get_send_status(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-1",
        invoice_ref="INV-1",
    )
    batch = adapters.get_send_status(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-2",
        invoice_ref=None,
    )

    assert online["status_code"] == 200
    assert online["ksef_number"] == "KSEF-9"
    assert batch["status_code"] == 100
    assert batch["upo_ref"] == "UPO-9"


def test_list_invoices_uses_default_from_and_invoice_list_key(monkeypatch) -> None:
    class _Invoices:
        def query_invoice_metadata(self, payload, **kwargs):
            _ = (payload, kwargs)
            return {"invoiceList": [{"ksefReferenceNumber": "KSEF-X"}]}

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=_Invoices()),
    )

    result = adapters.list_invoices(
        profile="demo",
        base_url="https://example.invalid",
        date_from=None,
        date_to="2026-01-31",
        subject_type="Subject1",
        date_type="Issue",
        page_size=10,
        page_offset=0,
        sort_order="Desc",
    )
    assert result["count"] == 1
    assert result["items"][0]["ksefReferenceNumber"] == "KSEF-X"


def test_resolve_output_path_for_plain_path_segment() -> None:
    path = adapters._resolve_output_path("artifacts", default_filename="out.xml")
    assert path.as_posix().endswith("artifacts")


def test_resolve_output_path_uses_default_name_for_existing_directory(tmp_path) -> None:
    target_dir = tmp_path / "artifacts"
    target_dir.mkdir()
    path = adapters._resolve_output_path(str(target_dir), default_filename="out.xml")
    assert path == target_dir / "out.xml"


def test_resolve_output_path_uses_default_name_when_path_has_trailing_separator() -> None:
    path = adapters._resolve_output_path("artifacts/", default_filename="out.xml")
    assert path.as_posix().endswith("artifacts/out.xml")

    win_path = adapters._resolve_output_path("artifacts\\", default_filename="out.xml")
    assert win_path.as_posix().endswith("artifacts/out.xml")


def test_safe_child_path_rejects_traversal(tmp_path) -> None:
    with pytest.raises(CliError) as exc:
        adapters._safe_child_path(tmp_path, "../outside.xml")
    assert exc.value.code == ExitCode.IO_ERROR


def test_build_form_code_validation() -> None:
    with pytest.raises(CliError) as exc:
        adapters._build_form_code(" ", "1", "FA")
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_load_invoice_xml_missing_and_empty(tmp_path) -> None:
    with pytest.raises(CliError) as missing:
        adapters._load_invoice_xml(str(tmp_path / "nope.xml"))
    assert missing.value.code == ExitCode.IO_ERROR

    empty = tmp_path / "empty.xml"
    empty.write_bytes(b"")
    with pytest.raises(CliError) as empty_exc:
        adapters._load_invoice_xml(str(empty))
    assert empty_exc.value.code == ExitCode.IO_ERROR


def test_load_batch_zip_missing_and_empty(tmp_path) -> None:
    with pytest.raises(CliError) as missing:
        adapters._load_batch_zip(str(tmp_path / "nope.zip"))
    assert missing.value.code == ExitCode.IO_ERROR

    empty = tmp_path / "empty.zip"
    empty.write_bytes(b"")
    with pytest.raises(CliError) as empty_exc:
        adapters._load_batch_zip(str(empty))
    assert empty_exc.value.code == ExitCode.IO_ERROR


def test_build_zip_from_directory_errors(tmp_path) -> None:
    with pytest.raises(CliError) as missing:
        adapters._build_zip_from_directory(str(tmp_path / "missing"))
    assert missing.value.code == ExitCode.IO_ERROR

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    with pytest.raises(CliError) as no_xml:
        adapters._build_zip_from_directory(str(empty_dir))
    assert no_xml.value.code == ExitCode.VALIDATION_ERROR


def test_wait_for_invoice_status_failed_and_timeout(monkeypatch) -> None:
    class _FailedSessions:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return {"status": {"code": 300, "description": "Rejected", "details": ["x", "y"]}}

    class _PendingSessions:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return {"status": {"code": 100, "description": "Pending"}}

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)
    with pytest.raises(CliError) as failed:
        adapters._wait_for_invoice_status(
            client=_FakeClient(sessions=_FailedSessions()),
            session_ref="s",
            invoice_ref="i",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert failed.value.code == ExitCode.API_ERROR

    with pytest.raises(CliError) as timeout:
        adapters._wait_for_invoice_status(
            client=_FakeClient(sessions=_PendingSessions()),
            session_ref="s",
            invoice_ref="i",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=2,
        )
    assert timeout.value.code == ExitCode.RETRY_EXHAUSTED


def test_wait_for_invoice_status_handles_http_errors(monkeypatch) -> None:
    class _TransientThenDone:
        def __init__(self) -> None:
            self.calls = 0

        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            self.calls += 1
            if self.calls == 1:
                raise KsefHttpError(status_code=404, message="wait")
            return {"status": {"code": 200, "description": "Done"}}

    class _Fatal:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)
    payload = adapters._wait_for_invoice_status(
        client=_FakeClient(sessions=_TransientThenDone()),
        session_ref="s",
        invoice_ref="i",
        access_token="acc",
        poll_interval=0.01,
        max_attempts=2,
    )
    assert int((payload.get("status") or {}).get("code", 0)) == 200

    with pytest.raises(KsefHttpError):
        adapters._wait_for_invoice_status(
            client=_FakeClient(sessions=_Fatal()),
            session_ref="s",
            invoice_ref="i",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )


def test_wait_for_invoice_upo_non_transient_and_timeout(monkeypatch) -> None:
    class _ErrSessions:
        def get_session_invoice_upo_by_ref(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    class _TransientSessions:
        def get_session_invoice_upo_by_ref(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            raise KsefHttpError(status_code=404, message="wait")

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    with pytest.raises(KsefHttpError):
        adapters._wait_for_invoice_upo(
            client=_FakeClient(sessions=_ErrSessions()),
            session_ref="s",
            invoice_ref="i",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )

    with pytest.raises(CliError) as timeout:
        adapters._wait_for_invoice_upo(
            client=_FakeClient(sessions=_TransientSessions()),
            session_ref="s",
            invoice_ref="i",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=2,
        )
    assert timeout.value.code == ExitCode.RETRY_EXHAUSTED


def test_wait_for_session_status_failed_and_timeout(monkeypatch) -> None:
    class _FailedSessions:
        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            return {"status": {"code": 300, "description": "Rejected", "details": ["x"]}}

    class _PendingSessions:
        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            return {"status": {"code": 150, "description": "Pending"}}

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    with pytest.raises(CliError) as failed:
        adapters._wait_for_session_status(
            client=_FakeClient(sessions=_FailedSessions()),
            session_ref="s",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert failed.value.code == ExitCode.API_ERROR

    with pytest.raises(CliError) as timeout:
        adapters._wait_for_session_status(
            client=_FakeClient(sessions=_PendingSessions()),
            session_ref="s",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=2,
        )
    assert timeout.value.code == ExitCode.RETRY_EXHAUSTED


def test_wait_for_session_status_handles_http_errors(monkeypatch) -> None:
    class _TransientThenDone:
        def __init__(self) -> None:
            self.calls = 0

        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            self.calls += 1
            if self.calls == 1:
                raise KsefHttpError(status_code=409, message="wait")
            return {"status": {"code": 200, "description": "Done"}}

    class _Fatal:
        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)
    payload = adapters._wait_for_session_status(
        client=_FakeClient(sessions=_TransientThenDone()),
        session_ref="s",
        access_token="acc",
        poll_interval=0.01,
        max_attempts=2,
    )
    assert int((payload.get("status") or {}).get("code", 0)) == 200

    with pytest.raises(KsefHttpError):
        adapters._wait_for_session_status(
            client=_FakeClient(sessions=_Fatal()),
            session_ref="s",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )


def test_wait_for_batch_upo_non_transient_and_timeout(monkeypatch) -> None:
    class _ErrSessions:
        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    class _TransientSessions:
        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            raise KsefHttpError(status_code=404, message="wait")

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    with pytest.raises(KsefHttpError):
        adapters._wait_for_batch_upo(
            client=_FakeClient(sessions=_ErrSessions()),
            session_ref="s",
            upo_ref="u",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )

    with pytest.raises(CliError) as timeout:
        adapters._wait_for_batch_upo(
            client=_FakeClient(sessions=_TransientSessions()),
            session_ref="s",
            upo_ref="u",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=2,
        )
    assert timeout.value.code == ExitCode.RETRY_EXHAUSTED


def test_download_invoice_rejects_unsupported_format(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    with pytest.raises(CliError) as exc:
        adapters.download_invoice(
            profile="demo",
            base_url="https://example.invalid",
            ksef_number="KSEF-1",
            out="invoice.xml",
            as_format="pdf",
            overwrite=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_get_upo_by_ksef_and_upo_ref(monkeypatch, tmp_path) -> None:
    class _Sessions:
        def get_session_invoice_upo_by_ksef(self, session_ref, ksef_number, access_token):
            _ = (session_ref, ksef_number, access_token)
            return b"<upo-ksef/>"

        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            return b"<upo-batch/>"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )

    ksef_path = tmp_path / "ksef.xml"
    upo_path = tmp_path / "upo.xml"
    ksef_result = adapters.get_upo(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-1",
        invoice_ref=None,
        ksef_number="KSEF-1",
        upo_ref=None,
        out=str(ksef_path),
        overwrite=False,
    )
    upo_result = adapters.get_upo(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-2",
        invoice_ref=None,
        ksef_number=None,
        upo_ref="UPO-1",
        out=str(upo_path),
        overwrite=False,
    )

    assert ksef_result["bytes"] == len(b"<upo-ksef/>")
    assert upo_result["bytes"] == len(b"<upo-batch/>")


def test_wait_for_upo_requires_one_mode(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    with pytest.raises(CliError) as exc:
        adapters.wait_for_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-1",
            invoice_ref=None,
            upo_ref=None,
            batch_auto=False,
            poll_interval=1.0,
            max_attempts=1,
            out=None,
            overwrite=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_wait_for_upo_non_transient_errors_are_raised(monkeypatch) -> None:
    class _SessionsDetected:
        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    class _SessionsInvoiceStatus:
        def get_session_invoice_status(self, session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    class _SessionsStatus:
        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_SessionsInvoiceStatus()),
    )
    with pytest.raises(KsefHttpError):
        adapters.wait_for_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-1",
            invoice_ref="INV-1",
            upo_ref=None,
            batch_auto=False,
            poll_interval=0.01,
            max_attempts=1,
            out=None,
            overwrite=False,
        )

    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_SessionsDetected()),
    )
    with pytest.raises(KsefHttpError):
        adapters.wait_for_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-1",
            invoice_ref=None,
            upo_ref="UPO-1",
            batch_auto=False,
            poll_interval=0.01,
            max_attempts=1,
            out=None,
            overwrite=False,
        )

    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_SessionsStatus()),
    )
    with pytest.raises(KsefHttpError):
        adapters.wait_for_upo(
            profile="demo",
            base_url="https://example.invalid",
            session_ref="SES-1",
            invoice_ref=None,
            upo_ref=None,
            batch_auto=True,
            poll_interval=0.01,
            max_attempts=1,
            out=None,
            overwrite=False,
        )


def test_send_online_invoice_missing_reference_and_failed_close(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _OnlineWorkflowMissingRef:
        def __init__(self, sessions):
            _ = sessions

        def open_session(self, *, form_code, public_certificate, access_token, upo_v43=False):
            _ = (form_code, public_certificate, access_token, upo_v43)
            return SimpleNamespace(
                session_reference_number="SES-ONLINE-X",
                encryption_data=SimpleNamespace(key=b"k", iv=b"i"),
            )

        def send_invoice(self, **kwargs):
            _ = kwargs
            return {}

        def close_session(self, reference_number, access_token):
            _ = (reference_number, access_token)
            raise RuntimeError("close failed")

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _OnlineWorkflowMissingRef)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=SimpleNamespace(), security=_Security()
        ),
    )

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<faktura/>", encoding="utf-8")

    with pytest.raises(CliError) as exc:
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
        )
    assert exc.value.code == ExitCode.API_ERROR


def test_send_batch_invoices_validates_parallelism_and_save_dependency(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    with pytest.raises(CliError) as parallel:
        adapters.send_batch_invoices(
            profile="demo",
            base_url="https://example.invalid",
            zip_path=str(zip_path),
            directory=None,
            system_code="FA (3)",
            schema_version="1-0E",
            form_value="FA",
            parallelism=0,
            upo_v43=False,
            wait_status=False,
            wait_upo=False,
            poll_interval=1.0,
            max_attempts=1,
            save_upo=None,
        )
    assert parallel.value.code == ExitCode.VALIDATION_ERROR

    with pytest.raises(CliError) as save_dep:
        adapters.send_batch_invoices(
            profile="demo",
            base_url="https://example.invalid",
            zip_path=str(zip_path),
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
            save_upo=str(tmp_path / "upo.xml"),
        )
    assert save_dep.value.code == ExitCode.VALIDATION_ERROR


def test_send_batch_invoices_wait_upo_without_save_sets_empty_path(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            return {"status": {"code": 200, "description": "Done"}, "upoReferenceNumber": "UPO-B-2"}

        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            return b"<upo-batch-2/>"

    class _BatchWorkflow:
        def __init__(self, sessions, http_client):
            _ = (sessions, http_client)

        def open_upload_and_close(self, **kwargs):
            _ = kwargs
            return "SES-BATCH-4"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _BatchWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=_Sessions(),
            security=_Security(),
            http_client=SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x03\x04")
    result = adapters.send_batch_invoices(
        profile="demo",
        base_url="https://example.invalid",
        zip_path=str(zip_path),
        directory=None,
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        parallelism=1,
        upo_v43=False,
        wait_status=True,
        wait_upo=True,
        poll_interval=0.01,
        max_attempts=1,
        save_upo=None,
    )

    assert result["upo_path"] == ""


def test_wait_for_upo_batch_auto_transient_session_status_then_success(monkeypatch) -> None:
    class _Sessions:
        def __init__(self) -> None:
            self.calls = 0

        def get_session_status(self, session_ref, access_token):
            _ = (session_ref, access_token)
            self.calls += 1
            if self.calls == 1:
                raise KsefHttpError(status_code=404, message="not yet")
            return {"upoReferenceNumber": "UPO-OK"}

        def get_session_upo(self, session_ref, upo_ref, access_token):
            _ = (session_ref, upo_ref, access_token)
            return b"<upo/>"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions()),
    )
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    result = adapters.wait_for_upo(
        profile="demo",
        base_url="https://example.invalid",
        session_ref="SES-TRANSIENT",
        invoice_ref=None,
        upo_ref=None,
        batch_auto=True,
        poll_interval=0.01,
        max_attempts=3,
        out=None,
        overwrite=False,
    )
    assert result["upo_ref"] == "UPO-OK"


def test_send_online_invoice_sets_empty_ksef_and_upo_path_without_save(
    monkeypatch, tmp_path
) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        pass

    class _OnlineWorkflow:
        def __init__(self, sessions):
            _ = sessions

        def open_session(self, *, form_code, public_certificate, access_token, upo_v43=False):
            _ = (form_code, public_certificate, access_token, upo_v43)
            return SimpleNamespace(
                session_reference_number="SES-NO-KSEF",
                encryption_data=SimpleNamespace(key=b"k", iv=b"i"),
            )

        def send_invoice(self, **kwargs):
            _ = kwargs
            return {"referenceNumber": "INV-NO-KSEF"}

        def close_session(self, reference_number, access_token):
            _ = (reference_number, access_token)

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _OnlineWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions(), security=_Security()),
    )
    monkeypatch.setattr(
        adapters,
        "_wait_for_invoice_status",
        lambda **kwargs: {"status": {"code": 200, "description": "Accepted"}},
    )
    monkeypatch.setattr(adapters, "_wait_for_invoice_upo", lambda **kwargs: b"<upo/>")

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")
    result = adapters.send_online_invoice(
        profile="demo",
        base_url="https://example.invalid",
        invoice=str(invoice_path),
        system_code="FA (3)",
        schema_version="1-0E",
        form_value="FA",
        upo_v43=False,
        wait_status=True,
        wait_upo=True,
        poll_interval=0.01,
        max_attempts=1,
        save_upo=None,
    )
    assert result["ksef_number"] == ""
    assert result["upo_path"] == ""


def test_wait_for_export_status_pending_fail_and_timeout(monkeypatch) -> None:
    class _PendingThenDone:
        def __init__(self) -> None:
            self.calls = 0

        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            self.calls += 1
            if self.calls == 1:
                return {"status": {"code": 100, "description": "Processing"}}
            return {"status": {"code": 200, "description": "Done"}}

    class _Failed:
        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {"status": {"code": 400, "description": "Failed", "details": ["x"]}}

    class _PendingForever:
        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {"status": {"code": 150, "description": "Still"}}

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)
    success = adapters._wait_for_export_status(
        client=_FakeClient(invoices=_PendingThenDone()),
        reference_number="EXP-1",
        access_token="acc",
        poll_interval=0.01,
        max_attempts=2,
    )
    assert success["status"]["code"] == 200

    with pytest.raises(CliError) as failed:
        adapters._wait_for_export_status(
            client=_FakeClient(invoices=_Failed()),
            reference_number="EXP-2",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert failed.value.code == ExitCode.API_ERROR

    with pytest.raises(CliError) as timeout:
        adapters._wait_for_export_status(
            client=_FakeClient(invoices=_PendingForever()),
            reference_number="EXP-3",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=2,
        )
    assert timeout.value.code == ExitCode.RETRY_EXHAUSTED


def test_wait_for_export_status_handles_http_transient_and_non_transient(monkeypatch) -> None:
    class _TransientThenOk:
        def __init__(self) -> None:
            self.calls = 0

        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            self.calls += 1
            if self.calls == 1:
                raise KsefHttpError(status_code=503, message="retry")
            return {"status": {"code": 200, "description": "Done"}}

    class _Fatal:
        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            raise KsefHttpError(status_code=500, message="fatal")

    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)
    ok = adapters._wait_for_export_status(
        client=_FakeClient(invoices=_TransientThenOk()),
        reference_number="EXP-HTTP-1",
        access_token="acc",
        poll_interval=0.01,
        max_attempts=2,
    )
    assert ok["status"]["code"] == 200

    with pytest.raises(KsefHttpError):
        adapters._wait_for_export_status(
            client=_FakeClient(invoices=_Fatal()),
            reference_number="EXP-HTTP-2",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )


def test_run_export_success(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Invoices:
        def export_invoices(self, payload, access_token):
            _ = (payload, access_token)
            return {"referenceNumber": "EXP-OK"}

        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {"status": {"code": 200, "description": "Done"}, "package": {"parts": []}}

    class _FakeExportWorkflow:
        def __init__(self, invoices_client, http_client):
            _ = (invoices_client, http_client)

        def download_and_process_package(self, package, encryption_data):
            _ = (package, encryption_data)
            return SimpleNamespace(
                metadata_summaries=[{"ksefNumber": "KSEF-1"}],
                invoice_xml_files={"a.xml": "<xml/>"},
            )

    fake_encryption = SimpleNamespace(
        key=b"k",
        iv=b"i",
        encryption_info=SimpleNamespace(
            encrypted_symmetric_key="enc",
            initialization_vector="iv",
        ),
    )

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            invoices=_Invoices(), security=_Security(), http_client=SimpleNamespace()
        ),
    )
    monkeypatch.setattr(adapters, "build_encryption_data", lambda cert: fake_encryption)
    monkeypatch.setattr(adapters, "ExportWorkflow", _FakeExportWorkflow)
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    result = adapters.run_export(
        profile="demo",
        base_url="https://example.invalid",
        date_from="2026-01-01",
        date_to="2026-01-31",
        subject_type="Subject1",
        poll_interval=0.01,
        max_attempts=2,
        out=str(tmp_path),
    )
    assert result["reference_number"] == "EXP-OK"
    assert result["metadata_count"] == 1
    assert (tmp_path / "_metadata.json").exists()
    assert (tmp_path / "a.xml").read_text(encoding="utf-8") == "<xml/>"


def test_run_export_missing_reference_and_package(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _InvoicesNoRef:
        def export_invoices(self, payload, access_token):
            _ = (payload, access_token)
            return {}

    class _InvoicesNoPackage:
        def export_invoices(self, payload, access_token):
            _ = (payload, access_token)
            return {"referenceNumber": "EXP-X"}

        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {"status": {"code": 200, "description": "Done"}}

    fake_encryption = SimpleNamespace(
        key=b"k",
        iv=b"i",
        encryption_info=SimpleNamespace(
            encrypted_symmetric_key="enc",
            initialization_vector="iv",
        ),
    )

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "build_encryption_data", lambda cert: fake_encryption)
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            invoices=_InvoicesNoRef(), security=_Security(), http_client=SimpleNamespace()
        ),
    )
    with pytest.raises(CliError) as no_ref:
        adapters.run_export(
            profile="demo",
            base_url="https://example.invalid",
            date_from=None,
            date_to=None,
            subject_type="Subject1",
            poll_interval=0.01,
            max_attempts=1,
            out=str(tmp_path),
        )
    assert no_ref.value.code == ExitCode.API_ERROR

    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            invoices=_InvoicesNoPackage(),
            security=_Security(),
            http_client=SimpleNamespace(),
        ),
    )
    with pytest.raises(CliError) as no_package:
        adapters.run_export(
            profile="demo",
            base_url="https://example.invalid",
            date_from=None,
            date_to=None,
            subject_type="Subject1",
            poll_interval=0.01,
            max_attempts=1,
            out=str(tmp_path),
        )
    assert no_package.value.code == ExitCode.API_ERROR


def test_get_export_status_success(monkeypatch) -> None:
    class _Invoices:
        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {"status": {"code": 200, "description": "Done"}}

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(invoices=_Invoices()),
    )

    result = adapters.get_export_status(
        profile="demo", base_url="https://example.invalid", reference="EXP-1"
    )
    assert result["status_code"] == 200
    assert result["reference_number"] == "EXP-1"


def test_run_health_check_variants(monkeypatch) -> None:
    class _SecurityClient:
        def get_public_key_certificates(self):
            return [
                {"usage": ["KsefTokenEncryption"], "certificate": "A"},
                {"usage": ["SymmetricKeyEncryption"], "certificate": "B"},
            ]

    class _SecurityClientMissing:
        def get_public_key_certificates(self):
            return [{"usage": ["KsefTokenEncryption"], "certificate": "A"}]

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(security=_SecurityClient()),
    )
    ok = adapters.run_health_check(
        profile="demo",
        base_url="https://example.invalid",
        dry_run=True,
        check_auth=False,
        check_certs=True,
    )
    assert ok["overall"] == "PASS"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: None)
    warn = adapters.run_health_check(
        profile="demo",
        base_url="https://example.invalid",
        dry_run=False,
        check_auth=False,
        check_certs=False,
    )
    assert warn["overall"] == "WARN"
    dry_run_warn = adapters.run_health_check(
        profile="demo",
        base_url="https://example.invalid",
        dry_run=True,
        check_auth=False,
        check_certs=False,
    )
    assert dry_run_warn["overall"] == "WARN"
    certificates = [item for item in dry_run_warn["checks"] if item["name"] == "certificates"]
    assert certificates and certificates[0]["status"] == "WARN"

    with pytest.raises(CliError) as auth_required:
        adapters.run_health_check(
            profile="demo",
            base_url="https://example.invalid",
            dry_run=False,
            check_auth=True,
            check_certs=False,
        )
    assert auth_required.value.code == ExitCode.AUTH_ERROR
    with pytest.raises(CliError) as certs_require_token:
        adapters.run_health_check(
            profile="demo",
            base_url="https://example.invalid",
            dry_run=False,
            check_auth=False,
            check_certs=True,
        )
    assert certs_require_token.value.code == ExitCode.AUTH_ERROR

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(security=_SecurityClientMissing()),
    )
    with pytest.raises(CliError) as cert_missing:
        adapters.run_health_check(
            profile="demo",
            base_url="https://example.invalid",
            dry_run=False,
            check_auth=False,
            check_certs=True,
        )
    assert cert_missing.value.code == ExitCode.API_ERROR

    fail = adapters.run_health_check(
        profile="demo",
        base_url="   ",
        dry_run=False,
        check_auth=False,
        check_certs=False,
    )
    assert fail["overall"] == "FAIL"
