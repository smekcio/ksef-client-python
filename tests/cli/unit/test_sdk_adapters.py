from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from ksef_client import models as m
from ksef_client.cli.commands import export_cmd
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


class _ToDictPayload:
    def to_dict(self):
        return {"value": "ok"}


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
    assert result["has_more"] is True
    assert result["is_truncated"] is False
    assert result["permanent_storage_hwm_date"] == ""
    assert seen["page_size"] == 10
    assert seen["sort_order"] == "Desc"
    payload = seen["payload"]
    assert isinstance(payload, m.InvoiceQueryFilters)
    assert payload.subject_type.value == "Subject1"


def test_to_output_payload_variants() -> None:
    assert adapters._to_output_payload({"x": 1}) == {"x": 1}
    assert adapters._to_output_payload(_ToDictPayload()) == {"value": "ok"}
    marker = object()
    assert adapters._to_output_payload(marker) is marker


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


def test_list_invoices_rejects_date_range_longer_than_3_months(monkeypatch) -> None:
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
            date_from="2026-01-01",
            date_to="2026-04-02",
            subject_type="Subject1",
            date_type="Issue",
            page_size=10,
            page_offset=0,
            sort_order="Desc",
        )

    assert exc.value.code == ExitCode.VALIDATION_ERROR
    assert "3 months" in (exc.value.hint or "")


def test_list_invoices_accepts_date_range_exactly_3_months(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class _Invoices:
        def query_invoice_metadata(self, payload, **kwargs):
            _ = payload
            seen.update(kwargs)
            return {"invoices": []}

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
        date_to="2026-04-01",
        subject_type="Subject1",
        date_type="Issue",
        page_size=10,
        page_offset=0,
        sort_order="Desc",
    )

    assert result["count"] == 0
    assert seen["page_size"] == 10


def test_list_invoices_rejects_page_size_below_openapi_min(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call client")),
    )

    with pytest.raises(CliError) as exc:
        adapters.list_invoices(
            profile="demo",
            base_url="https://example.invalid",
            date_from="2026-01-01",
            date_to="2026-01-31",
            subject_type="Subject1",
            date_type="Issue",
            page_size=9,
            page_offset=0,
            sort_order="Desc",
        )

    assert exc.value.code == ExitCode.VALIDATION_ERROR
    assert "10 and 250" in (exc.value.hint or "")


def test_list_invoices_rejects_page_size_above_openapi_max(monkeypatch) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call client")),
    )

    with pytest.raises(CliError) as exc:
        adapters.list_invoices(
            profile="demo",
            base_url="https://example.invalid",
            date_from="2026-01-01",
            date_to="2026-01-31",
            subject_type="Subject1",
            date_type="Issue",
            page_size=251,
            page_offset=0,
            sort_order="Desc",
        )

    assert exc.value.code == ExitCode.VALIDATION_ERROR
    assert "10 and 250" in (exc.value.hint or "")


def test_list_invoices_rejects_invalid_subject_type(monkeypatch) -> None:
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
            date_from="2026-01-01",
            date_to="2026-01-31",
            subject_type="bad-value",
            date_type="Issue",
            page_size=10,
            page_offset=0,
            sort_order="Desc",
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_list_invoices_rejects_invalid_date_type(monkeypatch) -> None:
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
            date_from="2026-01-01",
            date_to="2026-01-31",
            subject_type="Subject1",
            date_type="bad-value",
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
    assert result["has_more"] is False
    assert result["is_truncated"] is False
    assert result["permanent_storage_hwm_date"] == ""


def test_list_invoices_without_subject_type_queries_all_subject_types(monkeypatch) -> None:
    seen_calls: list[tuple[str, int, int]] = []

    responses = {
        ("Subject1", 0): {
            "invoices": [
                {"ksefNumber": "KSEF-2", "issueDate": "2026-01-03T00:00:00Z"},
                {"ksefNumber": "KSEF-DUP", "issueDate": "2026-01-02T00:00:00Z"},
            ],
            "hasMore": False,
        },
        ("Subject2", 0): {
            "invoices": [{"ksefNumber": "KSEF-3", "issueDate": "2026-01-04T00:00:00Z"}],
            "isTruncated": True,
            "permanentStorageHwmDate": "2026-01-31T23:59:59Z",
        },
        ("Subject3", 0): {
            "invoices": [{"ksefNumber": "KSEF-1", "issueDate": "2026-01-01T00:00:00Z"}]
        },
        ("SubjectAuthorized", 0): {
            "invoices": [{"ksefNumber": "KSEF-DUP", "issueDate": "2026-01-02T00:00:00Z"}]
        },
    }

    class _Invoices:
        def query_invoice_metadata(self, payload, **kwargs):
            subject_type = payload.subject_type.value
            page_offset = int(kwargs.get("page_offset", 0) or 0)
            page_size = int(kwargs.get("page_size", 0) or 0)
            seen_calls.append((subject_type, page_offset, page_size))
            return responses[(subject_type, page_offset)]

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
        subject_type=None,
        date_type="Issue",
        page_size=10,
        page_offset=0,
        sort_order="Desc",
    )

    assert seen_calls == [
        ("Subject1", 0, 10),
        ("Subject2", 0, 10),
        ("Subject3", 0, 10),
        ("SubjectAuthorized", 0, 10),
    ]
    assert result["count"] == 4
    assert [item["ksefNumber"] for item in result["items"]] == [
        "KSEF-3",
        "KSEF-2",
        "KSEF-DUP",
        "KSEF-1",
    ]
    assert result["continuation_token"] == ""
    assert result["has_more"] is False
    assert result["is_truncated"] is True
    assert result["permanent_storage_hwm_date"] == "2026-01-31T23:59:59Z"


def test_list_invoices_without_subject_type_aggregates_lowest_hwm_date(monkeypatch) -> None:
    responses = {
        ("Subject1", 0): {
            "invoices": [{"ksefNumber": "KSEF-1", "issueDate": "2026-01-01T00:00:00Z"}],
            "permanentStorageHwmDate": "2026-02-10T00:00:00Z",
        },
        ("Subject2", 0): {
            "invoices": [{"ksefNumber": "KSEF-2", "issueDate": "2026-01-02T00:00:00Z"}],
            "permanentStorageHwmDate": "2026-01-15T00:00:00Z",
        },
        ("Subject3", 0): {
            "invoices": [{"ksefNumber": "KSEF-3", "issueDate": "2026-01-03T00:00:00Z"}],
            "permanentStorageHwmDate": "2026-01-20T00:00:00Z",
        },
        ("SubjectAuthorized", 0): {
            "invoices": [{"ksefNumber": "KSEF-4", "issueDate": "2026-01-04T00:00:00Z"}]
        },
    }

    class _Invoices:
        def query_invoice_metadata(self, payload, **kwargs):
            subject_type = payload.subject_type.value
            page_offset = int(kwargs.get("page_offset", 0) or 0)
            return responses[(subject_type, page_offset)]

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
        subject_type=None,
        date_type="Issue",
        page_size=10,
        page_offset=0,
        sort_order="Asc",
    )

    assert result["count"] == 4
    assert result["permanent_storage_hwm_date"] == "2026-01-15T00:00:00Z"


def test_invoice_sort_value_handles_empty_invalid_and_naive_datetime() -> None:
    assert adapters._normalize_invoice_sort_value(None) == ""
    assert adapters._normalize_invoice_sort_value("   ") == ""
    assert adapters._normalize_invoice_sort_value("not-a-date") == "not-a-date"
    assert adapters._normalize_invoice_sort_value("2026-01-05T12:30:00") == (
        "2026-01-05T12:30:00+00:00"
    )


def test_invoice_identity_key_falls_back_to_serialized_payload_and_repr() -> None:
    class _PlainObject:
        pass

    payload_key = adapters._invoice_identity_key(_ToDictPayload())
    repr_key = adapters._invoice_identity_key(_PlainObject())

    assert payload_key == '{"value": "ok"}'
    assert "_PlainObject object" in repr_key


def test_query_all_invoice_subject_types_handles_negative_offset_and_bounded_page_size(
    monkeypatch,
) -> None:
    responses = {
        ("Subject1", 0): {
            "invoices": [{"ksefNumber": "KSEF-1", "issueDate": "2026-01-01T00:00:00Z"}]
        },
        ("Subject2", 0): {
            "invoices": [{"ksefNumber": "KSEF-3", "issueDate": "2026-01-03T00:00:00Z"}]
        },
        ("Subject3", 0): {
            "invoices": [{"ksefNumber": "KSEF-2", "issueDate": "2026-01-02T00:00:00Z"}]
        },
        ("SubjectAuthorized", 0): {"invoices": []},
    }

    def _fake_query_page(**kwargs):
        subject_type = kwargs["subject_type"].value
        page_offset = kwargs["page_offset"]
        return responses[(subject_type, page_offset)]

    monkeypatch.setattr(adapters, "_query_invoice_metadata_page", _fake_query_page)

    result = adapters._query_all_invoice_subject_types(
        client=object(),
        access_token="token",
        date_type=m.InvoiceQueryDateType.ISSUE,
        from_iso="2026-01-01T00:00:00Z",
        to_iso="2026-01-31T23:59:59Z",
        page_size=10,
        page_offset=-5,
        sort_order="Asc",
    )

    assert [item["ksefNumber"] for item in result["items"]] == ["KSEF-1", "KSEF-2", "KSEF-3"]
    assert result["has_more"] is False
    assert result["is_truncated"] is False
    assert result["permanent_storage_hwm_date"] == ""


def test_query_all_invoice_subject_types_has_more_false_when_followup_pages_only_duplicate(
    monkeypatch,
) -> None:
    seen_calls: list[tuple[str, int]] = []
    responses = {
        ("Subject1", 0): {
            "invoices": [
                {"ksefNumber": "KSEF-1", "issueDate": "2026-01-01T00:00:00Z"},
                {"ksefNumber": "KSEF-2", "issueDate": "2026-01-02T00:00:00Z"},
            ],
            "hasMore": True,
        },
        ("Subject1", 2): {
            "invoices": [
                {"ksefNumber": "KSEF-1", "issueDate": "2026-01-01T00:00:00Z"},
            ],
            "hasMore": False,
        },
        ("Subject2", 0): {"invoices": []},
        ("Subject3", 0): {"invoices": []},
        ("SubjectAuthorized", 0): {"invoices": []},
    }

    def _fake_query_page(**kwargs):
        subject_type = kwargs["subject_type"].value
        page_offset = kwargs["page_offset"]
        seen_calls.append((subject_type, page_offset))
        return responses[(subject_type, page_offset)]

    monkeypatch.setattr(adapters, "_query_invoice_metadata_page", _fake_query_page)

    result = adapters._query_all_invoice_subject_types(
        client=object(),
        access_token="token",
        date_type=m.InvoiceQueryDateType.ISSUE,
        from_iso="2026-01-01T00:00:00Z",
        to_iso="2026-01-31T23:59:59Z",
        page_size=2,
        page_offset=0,
        sort_order="Asc",
    )

    assert [item["ksefNumber"] for item in result["items"]] == ["KSEF-1", "KSEF-2"]
    assert ("Subject1", 2) in seen_calls
    assert result["has_more"] is False


def test_query_all_invoice_subject_types_page_size_zero_returns_unbounded_slice(
    monkeypatch,
) -> None:
    responses = {
        ("Subject1", 0): {
            "invoices": [{"ksefNumber": "KSEF-1", "issueDate": "2026-01-01T00:00:00Z"}]
        },
        ("Subject2", 0): {"invoices": []},
        ("Subject3", 0): {"invoices": []},
        ("SubjectAuthorized", 0): {"invoices": []},
    }

    def _fake_query_page(**kwargs):
        subject_type = kwargs["subject_type"].value
        page_offset = kwargs["page_offset"]
        return responses[(subject_type, page_offset)]

    monkeypatch.setattr(adapters, "_query_invoice_metadata_page", _fake_query_page)

    result = adapters._query_all_invoice_subject_types(
        client=object(),
        access_token="token",
        date_type=m.InvoiceQueryDateType.ISSUE,
        from_iso="2026-01-01T00:00:00Z",
        to_iso="2026-01-31T23:59:59Z",
        page_size=0,
        page_offset=0,
        sort_order="Asc",
    )

    assert [item["ksefNumber"] for item in result["items"]] == ["KSEF-1"]
    assert result["has_more"] is False


def test_query_all_invoice_subject_types_stops_at_limit_before_deeper_paging(monkeypatch) -> None:
    responses = {
        ("Subject1", 0): {
            "invoices": [
                {"ksefNumber": "KSEF-1", "issueDate": "2026-01-01T00:00:00Z"},
                {"ksefNumber": "KSEF-2", "issueDate": "2026-01-02T00:00:00Z"},
                {"ksefNumber": "KSEF-3", "issueDate": "2026-01-03T00:00:00Z"},
            ]
        },
        ("Subject2", 0): {"invoices": []},
        ("Subject3", 0): {"invoices": []},
        ("SubjectAuthorized", 0): {"invoices": []},
    }

    def _fake_query_page(**kwargs):
        subject_type = kwargs["subject_type"].value
        page_offset = kwargs["page_offset"]
        return responses[(subject_type, page_offset)]

    monkeypatch.setattr(adapters, "_query_invoice_metadata_page", _fake_query_page)

    result = adapters._query_all_invoice_subject_types(
        client=object(),
        access_token="token",
        date_type=m.InvoiceQueryDateType.ISSUE,
        from_iso="2026-01-01T00:00:00Z",
        to_iso="2026-01-31T23:59:59Z",
        page_size=1,
        page_offset=0,
        sort_order="Asc",
    )

    assert [item["ksefNumber"] for item in result["items"]] == ["KSEF-1"]
    assert result["has_more"] is True


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


def test_build_form_code_normalizes_fa_rr_1_1e_value() -> None:
    form_code = adapters._build_form_code("FA_RR (1)", "1-1E", "RR")
    assert form_code.value == "FA_RR"


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
    seen: dict[str, object] = {}

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Invoices:
        def export_invoices(self, payload, access_token):
            seen["payload"] = payload
            seen["access_token"] = access_token
            return {"referenceNumber": "EXP-OK"}

        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {
                "status": {"code": 200, "description": "Done"},
                "package": {
                    "invoiceCount": 0,
                    "size": 0,
                    "isTruncated": False,
                    "parts": [],
                },
            }

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
    assert result["only_metadata"] is False
    assert result["date_type"] == "Issue"
    assert result["restrict_to_permanent_storage_hwm_date"] is False
    payload = seen["payload"]
    assert isinstance(payload, m.InvoiceExportRequest)
    assert payload.only_metadata is False
    assert payload.filters.date_range.date_type == m.InvoiceQueryDateType.ISSUE
    assert payload.filters.date_range.restrict_to_permanent_storage_hwm_date is False
    assert (tmp_path / "_metadata.json").exists()
    assert (tmp_path / "a.xml").read_text(encoding="utf-8") == "<xml/>"


def test_run_export_only_metadata_success(monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Invoices:
        def export_invoices(self, payload, access_token):
            seen["payload"] = payload
            seen["access_token"] = access_token
            return {"referenceNumber": "EXP-META"}

        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {
                "status": {"code": 200, "description": "Done"},
                "package": {
                    "invoiceCount": 0,
                    "size": 0,
                    "isTruncated": False,
                    "parts": [
                        {
                            "ordinalNumber": 1,
                            "partName": "p1",
                            "method": "GET",
                            "url": "https://example.com",
                            "partSize": 1,
                            "partHash": "h",
                            "encryptedPartSize": 2,
                            "encryptedPartHash": "eh",
                            "expirationDate": "2026-03-27T12:00:00Z",
                        }
                    ],
                },
            }

    class _FakeExportWorkflow:
        def __init__(self, invoices, http_client):
            _ = (invoices, http_client)

        def download_and_process_package(self, package, encryption):
            _ = (package, encryption)
            return SimpleNamespace(
                metadata_summaries=[{"ksefNumber": "KSEF-1"}],
                invoice_xml_files={},
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
        only_metadata=True,
        poll_interval=0.01,
        max_attempts=2,
        out=str(tmp_path),
    )

    assert result["reference_number"] == "EXP-META"
    assert result["metadata_count"] == 1
    assert result["xml_files_count"] == 0
    assert result["only_metadata"] is True
    payload = seen["payload"]
    assert isinstance(payload, m.InvoiceExportRequest)
    assert payload.only_metadata is True
    assert (tmp_path / "_metadata.json").exists()
    assert list(tmp_path.glob("*.xml")) == []


def test_run_export_incremental_hwm_filters(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Invoices:
        def export_invoices(self, payload, access_token):
            seen["payload"] = payload
            seen["access_token"] = access_token
            return {"referenceNumber": "EXP-HWM"}

        def get_export_status(self, reference_number, access_token):
            _ = (reference_number, access_token)
            return {
                "status": {"code": 200, "description": "Done"},
                "package": {
                    "invoiceCount": 0,
                    "size": 0,
                    "isTruncated": False,
                    "parts": [],
                },
            }

    class _FakeExportWorkflow:
        def __init__(self, invoices_client, http_client):
            _ = (invoices_client, http_client)

        def download_and_process_package(self, package, encryption_data):
            _ = (package, encryption_data)
            return SimpleNamespace(metadata_summaries=[], invoice_xml_files={})

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

    out_dir = Path("build_test_export_hwm")
    out_dir.mkdir(parents=True, exist_ok=True)
    result = adapters.run_export(
        profile="demo",
        base_url="https://example.invalid",
        date_from="2026-01-01",
        date_to="2026-01-31",
        date_type="PermanentStorage",
        subject_type="Subject1",
        restrict_to_permanent_storage_hwm_date=True,
        poll_interval=0.01,
        max_attempts=2,
        out=str(out_dir),
    )

    assert result["reference_number"] == "EXP-HWM"
    assert result["date_type"] == "PermanentStorage"
    assert result["restrict_to_permanent_storage_hwm_date"] is True
    payload = seen["payload"]
    assert isinstance(payload, m.InvoiceExportRequest)
    assert payload.filters.date_range.date_type == m.InvoiceQueryDateType.PERMANENTSTORAGE
    assert payload.filters.date_range.restrict_to_permanent_storage_hwm_date is True


def test_export_run_cli_passes_incremental_options(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class _Renderer:
        def success(self, *, command, profile, data):
            seen["result"] = {"command": command, "profile": profile, "data": data}

    monkeypatch.setattr(export_cmd, "require_context", lambda ctx: SimpleNamespace(profile="demo"))
    monkeypatch.setattr(export_cmd, "get_renderer", lambda cli_ctx: _Renderer())
    monkeypatch.setattr(export_cmd, "profile_label", lambda cli_ctx: "demo")
    monkeypatch.setattr(export_cmd, "require_profile", lambda cli_ctx: "demo")
    monkeypatch.setattr(export_cmd, "resolve_base_url", lambda value, profile: value or "https://example.invalid")
    monkeypatch.setattr(
        export_cmd,
        "run_export",
        lambda **kwargs: seen.setdefault("kwargs", kwargs) or {"ok": True},
    )

    export_cmd.export_run(
        ctx=SimpleNamespace(),
        date_from="2026-01-01",
        date_to="2026-01-31",
        date_type="PermanentStorage",
        subject_type="Subject1",
        restrict_to_permanent_storage_hwm_date=True,
        only_metadata=False,
        poll_interval=1.0,
        max_attempts=10,
        out=".",
        base_url="https://example.invalid",
    )

    assert seen["kwargs"]["date_type"] == "PermanentStorage"
    assert seen["kwargs"]["restrict_to_permanent_storage_hwm_date"] is True
    assert "sort_order" not in seen["kwargs"]


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


def test_run_export_requires_encryption_metadata(monkeypatch, tmp_path) -> None:
    class _Security:
        def get_public_key_certificates(self):
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    fake_encryption = adapters.EncryptionData(key=b"k" * 32, iv=b"i" * 16, encryption_info=None)

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "build_encryption_data", lambda cert: fake_encryption)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            invoices=SimpleNamespace(),
            security=_Security(),
            http_client=SimpleNamespace(),
        ),
    )

    with pytest.raises(CliError) as exc:
        adapters.run_export(
            profile="demo",
            base_url="https://example.invalid",
            date_from="2026-01-01",
            date_to="2026-01-31",
            subject_type="Subject1",
            poll_interval=0.01,
            max_attempts=1,
            out=str(tmp_path),
        )

    assert exc.value.code == ExitCode.CONFIG_ERROR


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


def test_build_zip_from_directory_skips_non_file_xml_paths(tmp_path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "invoice.xml").mkdir()
    with pytest.raises(CliError) as exc:
        adapters._build_zip_from_directory(str(tmp_path))
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_wait_helpers_include_details_in_error_hints(monkeypatch) -> None:
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    class _InvoiceStatusClient:
        class sessions:
            @staticmethod
            def get_session_invoice_status(session_ref, invoice_ref, access_token):
                _ = (session_ref, invoice_ref, access_token)
                return {"status": {"code": 400, "description": "bad", "details": ["d1"]}}

    class _SessionStatusClient:
        class sessions:
            @staticmethod
            def get_session_status(session_ref, access_token):
                _ = (session_ref, access_token)
                return {"status": {"code": 400, "description": "bad", "details": ["d2"]}}

    class _ExportStatusClient:
        class invoices:
            @staticmethod
            def get_export_status(reference_number, access_token):
                _ = (reference_number, access_token)
                return {"status": {"code": 400, "description": "bad", "details": ["d3"]}}

    with pytest.raises(CliError) as invoice_exc:
        adapters._wait_for_invoice_status(
            client=_InvoiceStatusClient(),
            session_ref="S",
            invoice_ref="I",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert "Details: d1" in (invoice_exc.value.hint or "")

    with pytest.raises(CliError) as session_exc:
        adapters._wait_for_session_status(
            client=_SessionStatusClient(),
            session_ref="S",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert "Details: d2" in (session_exc.value.hint or "")

    with pytest.raises(CliError) as export_exc:
        adapters._wait_for_export_status(
            client=_ExportStatusClient(),
            reference_number="R",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert "Details: d3" in (export_exc.value.hint or "")


def test_wait_helpers_error_hints_without_details(monkeypatch) -> None:
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    class _InvoiceStatusClient:
        class sessions:
            @staticmethod
            def get_session_invoice_status(session_ref, invoice_ref, access_token):
                _ = (session_ref, invoice_ref, access_token)
                return {"status": {"code": 400, "description": "bad"}}

    class _SessionStatusClient:
        class sessions:
            @staticmethod
            def get_session_status(session_ref, access_token):
                _ = (session_ref, access_token)
                return {"status": {"code": 400, "description": "bad"}}

    class _ExportStatusClient:
        class invoices:
            @staticmethod
            def get_export_status(reference_number, access_token):
                _ = (reference_number, access_token)
                return {"status": {"code": 400, "description": "bad"}}

    with pytest.raises(CliError) as invoice_exc:
        adapters._wait_for_invoice_status(
            client=_InvoiceStatusClient(),
            session_ref="S",
            invoice_ref="I",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert invoice_exc.value.hint == "bad"

    with pytest.raises(CliError) as session_exc:
        adapters._wait_for_session_status(
            client=_SessionStatusClient(),
            session_ref="S",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert session_exc.value.hint == "bad"

    with pytest.raises(CliError) as export_exc:
        adapters._wait_for_export_status(
            client=_ExportStatusClient(),
            reference_number="R",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert export_exc.value.hint == "bad"


def test_wait_helpers_retry_on_empty_upo_bytes(monkeypatch) -> None:
    monkeypatch.setattr(adapters.time, "sleep", lambda _: None)

    class _InvoiceUpoClient:
        class sessions:
            @staticmethod
            def get_session_invoice_upo_by_ref(session_ref, invoice_ref, access_token):
                _ = (session_ref, invoice_ref, access_token)
                return b""

    class _BatchUpoClient:
        class sessions:
            @staticmethod
            def get_session_upo(session_ref, upo_ref, access_token):
                _ = (session_ref, upo_ref, access_token)
                return b""

    with pytest.raises(CliError) as invoice_exc:
        adapters._wait_for_invoice_upo(
            client=_InvoiceUpoClient(),
            session_ref="S",
            invoice_ref="I",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert invoice_exc.value.code == ExitCode.RETRY_EXHAUSTED

    with pytest.raises(CliError) as batch_exc:
        adapters._wait_for_batch_upo(
            client=_BatchUpoClient(),
            session_ref="S",
            upo_ref="U",
            access_token="acc",
            poll_interval=0.01,
            max_attempts=1,
        )
    assert batch_exc.value.code == ExitCode.RETRY_EXHAUSTED


def test_wait_for_upo_invoice_ref_pending_status_times_out(monkeypatch) -> None:
    class _Sessions:
        @staticmethod
        def get_session_invoice_status(session_ref, invoice_ref, access_token):
            _ = (session_ref, invoice_ref, access_token)
            return {"status": {"code": 100}}

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
            session_ref="SES-PENDING",
            invoice_ref="INV-PENDING",
            upo_ref=None,
            batch_auto=False,
            poll_interval=0.01,
            max_attempts=1,
            out=None,
            overwrite=False,
        )
    assert exc.value.code == ExitCode.RETRY_EXHAUSTED


def test_send_online_invoice_success_without_waits(monkeypatch, tmp_path) -> None:
    class _Security:
        @staticmethod
        def get_public_key_certificates():
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        pass

    class _OnlineWorkflow:
        def __init__(self, sessions):
            _ = sessions

        def open_session(self, *, form_code, public_certificate, access_token, upo_v43=False):
            _ = (form_code, public_certificate, access_token, upo_v43)
            return SimpleNamespace(
                session_reference_number="SES-NO-WAIT",
                encryption_data=SimpleNamespace(key=b"k", iv=b"i"),
            )

        def send_invoice(self, **kwargs):
            _ = kwargs
            return {"referenceNumber": "INV-NO-WAIT"}

        def close_session(self, reference_number, access_token):
            _ = (reference_number, access_token)

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "OnlineSessionWorkflow", _OnlineWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(sessions=_Sessions(), security=_Security()),
    )

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
        wait_status=False,
        wait_upo=False,
        poll_interval=0.01,
        max_attempts=1,
        save_upo=None,
    )
    assert result == {"session_ref": "SES-NO-WAIT", "invoice_ref": "INV-NO-WAIT"}


def test_send_online_invoice_wait_status_without_wait_upo(monkeypatch, tmp_path) -> None:
    class _Security:
        @staticmethod
        def get_public_key_certificates():
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        pass

    class _OnlineWorkflow:
        def __init__(self, sessions):
            _ = sessions

        def open_session(self, *, form_code, public_certificate, access_token, upo_v43=False):
            _ = (form_code, public_certificate, access_token, upo_v43)
            return SimpleNamespace(
                session_reference_number="SES-STATUS-ONLY",
                encryption_data=SimpleNamespace(key=b"k", iv=b"i"),
            )

        def send_invoice(self, **kwargs):
            _ = kwargs
            return {"referenceNumber": "INV-STATUS-ONLY"}

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
        lambda **kwargs: {
            "status": {"code": 200, "description": "Accepted"},
            "ksefNumber": "KSEF-X",
        },
    )

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
        wait_upo=False,
        poll_interval=0.01,
        max_attempts=1,
        save_upo=None,
    )
    assert result["ksef_number"] == "KSEF-X"
    assert "upo_bytes" not in result


def test_send_batch_invoices_wait_status_without_wait_upo(monkeypatch, tmp_path) -> None:
    class _Security:
        @staticmethod
        def get_public_key_certificates():
            return [{"usage": ["SymmetricKeyEncryption"], "certificate": "CERT"}]

    class _Sessions:
        @staticmethod
        def get_session_status(session_ref, access_token):
            _ = (session_ref, access_token)
            return {"status": {"code": 200, "description": "Done"}, "upoReferenceNumber": "UPO-1"}

    class _BatchWorkflow:
        def __init__(self, sessions, http_client):
            _ = (sessions, http_client)

        @staticmethod
        def open_upload_and_close(**kwargs):
            _ = kwargs
            return "SES-BATCH-STATUS"

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(adapters, "BatchSessionWorkflow", _BatchWorkflow)
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(
            sessions=_Sessions(), security=_Security(), http_client=SimpleNamespace()
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
        wait_upo=False,
        poll_interval=0.01,
        max_attempts=1,
        save_upo=None,
    )
    assert result["session_ref"] == "SES-BATCH-STATUS"
    assert result["upo_ref"] == "UPO-1"
    assert "upo_path" not in result


def test_run_health_check_ignores_non_list_usage_values(monkeypatch) -> None:
    class _SecurityClient:
        @staticmethod
        def get_public_key_certificates():
            return [
                {"usage": "KsefTokenEncryption", "certificate": "A"},
                {"usage": ["SymmetricKeyEncryption"], "certificate": "B"},
            ]

    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(security=_SecurityClient()),
    )
    result = adapters.run_health_check(
        profile="demo",
        base_url="https://example.invalid",
        dry_run=True,
        check_auth=False,
        check_certs=False,
    )
    cert_check = [item for item in result["checks"] if item["name"] == "certificates"][0]
    assert cert_check["status"] == "FAIL"
