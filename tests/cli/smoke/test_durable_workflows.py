import base64
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ksef_client import Ksef
from ksef_client.cli import app
from ksef_client.cli.commands import _workflow
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.profiles import ProfileStore


def test_offline_enqueues_locally_and_isolates_profiles(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KSEF_OFFLINE_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    xml = tmp_path / "invoice.xml"
    xml.write_bytes(b"<Faktura/>")
    common = ["--state-dir", str(tmp_path / "private")]
    enqueue = runner.invoke(
        app,
        [
            "--json",
            "offline",
            "enqueue",
            *common,
            "--xml",
            str(xml),
            "--due-at",
            "2020-01-01T00:00:00Z",
        ],
    )
    assert enqueue.exit_code == 0, enqueue.output
    row = json.loads(enqueue.output)["data"]
    assert row["status"] == "queued"
    assert row["overdue"]
    status = runner.invoke(app, ["--json", "offline", "status", *common])
    assert json.loads(status.output)["data"] == {"invoices": [row]}
    ProfileStore.default().create("other", env="DEMO", context_type="nip", context_value="456")
    other = runner.invoke(app, ["--profile", "other", "--json", "offline", "status", *common])
    assert other.exit_code == ExitCode.CONFIG_ERROR
    assert row["invoice_hash"] not in other.output


def test_archive_rejects_cached_token_without_scope_binding(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KSEF_EXPORT_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    monkeypatch.setattr(_workflow, "get_tokens", lambda profile: ("cached", "refresh"))
    result = runner.invoke(
        app,
        [
            "--json",
            "archive",
            "sync",
            "--state-dir",
            str(tmp_path / "private"),
            "--since",
            "2026-01-01T00:00:00Z",
        ],
    )
    assert result.exit_code == ExitCode.AUTH_ERROR, result.output
    assert json.loads(result.output)["errors"][0]["code"] == "AUTH_ERROR"
    assert not (tmp_path / "private").exists()


def test_archive_status_preserves_watermark_across_cli_invocations(runner, tmp_path, monkeypatch):
    from contextlib import nullcontext

    from tests.test_invoice_export_package import END, START, package
    from tests.test_invoice_export_sync import Client, Export

    from ksef_client.cli.commands import archive_cmd
    from ksef_client.operations import environment_key

    class ArchiveClient(Client):
        def __init__(self, descriptor):
            super().__init__(descriptor)
            from ksef_client.facade import Exports

            self.environment = environment_key("https://api-demo.ksef.mf.gov.pl/v2")
            self.context_key = "Nip:123"
            self.exports.sync_archive = Exports(cast(Ksef, self)).sync_archive

    monkeypatch.setenv("KSEF_EXPORT_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", Export)
    source = tmp_path / "source"
    source.mkdir()
    client = ArchiveClient(package(source).package)
    monkeypatch.setattr(archive_cmd, "workflow_client", lambda *args: nullcontext(client))
    common = ["--state-dir", str(tmp_path / "private")]
    status = runner.invoke(app, ["--json", "archive", "status", *common])
    empty = json.loads(status.output)["data"]
    assert empty["status"] == "uninitialized" and empty["committed_hwm"] is None
    sync = ["--json", "archive", "sync", *common, "--since", START, "--until", END]
    first = runner.invoke(app, [*sync, "--max-documents", "1"])
    assert first.exit_code == 0, first.output
    assert json.loads(first.output)["data"]["status"] == "importing"
    status = runner.invoke(app, ["--json", "archive", "status", *common])
    assert status.exit_code == 0, status.output
    assert json.loads(status.output)["data"]["committed_hwm"] is None
    other_role = runner.invoke(app, ["--json", "archive", "status", *common, "--role", "Subject1"])
    assert json.loads(other_role.output)["data"]["status"] == "uninitialized"
    second = runner.invoke(app, sync)
    assert second.exit_code == 0, second.output
    status = runner.invoke(app, ["--json", "archive", "status", *common])
    assert json.loads(status.output)["data"]["committed_hwm"] == END
    assert client.downloads == len(client.requests) == 1


@pytest.mark.parametrize(
    ("retry_after", "expected_seconds"),
    [
        ({"retry_after": 17}, 17),
        ({"retry_after": 300, "retry_after_raw": "3600"}, 3600),
        ({}, None),
    ],
)
def test_offline_run_reconciles_lost_send_and_honors_429(
    runner, tmp_path, monkeypatch, retry_after, expected_seconds
):
    from contextlib import nullcontext

    from tests.test_offline_invoice_store import DUE, XML
    from tests.test_offline_invoices import TestClient

    from ksef_client.cli.commands import offline_cmd
    from ksef_client.exceptions import KsefRateLimitError
    from ksef_client.facade import Invoices
    from ksef_client.operations import environment_key

    class OfflineClient(TestClient):
        environment = environment_key("https://api-demo.ksef.mf.gov.pl/v2")
        context_key = "Nip:123"

        def __init__(self):
            super().__init__()
            self.invoices = Invoices(cast(Ksef, self))

        def online_session(self):
            if not self.failed_once:
                self.failed_once = True
                raise KsefRateLimitError(429, "rate limited", **retry_after)
            return super().online_session()

    monkeypatch.setenv("KSEF_OFFLINE_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    client = OfflineClient()
    other_client = OfflineClient()
    other_client.context_key = "Nip:456"
    other_client.failed_once = True
    ProfileStore.default().create("other", env="DEMO", context_type="nip", context_value="456")
    clients = {"demo": client, "other": other_client}
    monkeypatch.setattr(
        offline_cmd, "workflow_client", lambda name, *args: nullcontext(clients[name])
    )
    xml = tmp_path / "invoice.xml"
    xml.write_bytes(XML)
    common = ["--state-dir", str(tmp_path / "private")]
    enqueue = runner.invoke(
        app, ["--json", "offline", "enqueue", *common, "--xml", str(xml), "--due-at", DUE]
    )
    invoice = json.loads(enqueue.output)["data"]["invoice_hash"]
    run = ["--json", "offline", "run", *common]
    limited = runner.invoke(app, run)
    assert limited.exit_code == ExitCode.RETRY_EXHAUSTED
    assert json.loads(limited.output)["errors"][0].get("retry_after_seconds") == expected_seconds

    other = ["--profile", "other", "--json", "offline"]
    staged_other = runner.invoke(
        app, [*other, "enqueue", *common, "--xml", str(xml), "--due-at", DUE]
    )
    assert staged_other.exit_code == 0
    processed_other = runner.invoke(app, [*other, "run", *common])
    assert processed_other.exit_code == 0
    assert json.loads(processed_other.output)["data"]["invoices"][0]["status"] == "session_open"
    assert client.open_count == 0 and other_client.open_count == 1

    # KSeF session opening has a durable claim. A subsequent cycle can open it
    # after the failed owner's claim expires.
    monkeypatch.setattr(
        "ksef_client._offline_invoice_store.time",
        SimpleNamespace(time=lambda: 10**10),
    )
    opened = runner.invoke(app, run)
    assert json.loads(opened.output)["data"]["invoices"][0]["status"] == "session_open"
    assert runner.invoke(app, run).exit_code == ExitCode.IO_ERROR
    status = runner.invoke(app, ["--json", "offline", "status", *common, "--invoice-hash", invoice])
    assert json.loads(status.output)["data"]["status"] == "submission_unknown"

    accepted = json.loads(runner.invoke(app, run).output)["data"]["invoices"][0]
    assert accepted["status"] == "accepted"
    assert not accepted["overdue"]
    assert runner.invoke(app, run).exit_code == ExitCode.IO_ERROR
    assert runner.invoke(app, run).exit_code == ExitCode.IO_ERROR
    assert json.loads(runner.invoke(app, run).output)["data"]["invoices"][0]["status"] == "complete"
    assert client.send_count == 1

    out = tmp_path / "receipt.xml"
    export = ["--json", "offline", "upo", *common, "--invoice-hash", invoice, "--out", str(out)]
    assert runner.invoke(app, export).exit_code == 0
    assert out.read_bytes() == b"<UPO/>"
    out.write_bytes(b"existing")
    assert runner.invoke(app, export).exit_code == ExitCode.IO_ERROR
    assert out.read_bytes() == b"existing"


@pytest.mark.parametrize("key", ["not/base64!", ""])
def test_cli_rejects_missing_or_invalid_workflow_key(runner, tmp_path, monkeypatch, key):
    monkeypatch.setenv("KSEF_OFFLINE_STATE_KEY", key)
    result = runner.invoke(
        app, ["--json", "offline", "status", "--state-dir", str(tmp_path / "private")]
    )
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert json.loads(result.output)["errors"][0]["code"] == "CONFIG_ERROR"
    assert "KSEF_OFFLINE_STATE_KEY" in result.output


def test_offline_status_paginates_and_validates_input(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KSEF_OFFLINE_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    common = ["--state-dir", str(tmp_path / "private")]
    statuses = ["--json", "offline", "status", *common]
    invoices = []
    for index in range(2):
        xml = tmp_path / f"invoice-{index}.xml"
        xml.write_bytes(f"<Invoice>{index}</Invoice>".encode())
        args = [
            "--json",
            "offline",
            "enqueue",
            *common,
            "--xml",
            str(xml),
            "--due-at",
            f"2020-01-0{index + 1}T00:00:00Z",
        ]
        result = runner.invoke(app, args)
        assert result.exit_code == 0
        invoices.append(json.loads(result.output)["data"])
    first = invoices[0]
    result = runner.invoke(
        app, [*statuses, "--after-due-at", first["due_at"], "--after-hash", first["invoice_hash"]]
    )
    assert json.loads(result.output)["data"]["invoices"] == invoices[1:]
    assert runner.invoke(app, [*statuses, "--after-due-at", first["due_at"]]).exit_code == 2
    assert (
        runner.invoke(
            app, [*statuses, "--invoice-hash", base64.b64encode(bytes(32)).decode()]
        ).exit_code
        == 2
    )

    invalid = runner.invoke(
        app, ["--json", "offline", "enqueue", *common, "--xml", str(xml), "--due-at", "tomorrow"]
    )
    assert invalid.exit_code == ExitCode.VALIDATION_ERROR
    assert "timestamp" in invalid.output

    reschedule = [
        "offline",
        "reschedule",
        *common,
        "--invoice-hash",
        first["invoice_hash"],
        "--due-at",
        "2030-01-01T00:00:00Z",
        "--revision",
        str(first["revision"]),
    ]
    result = runner.invoke(app, ["--json", *reschedule])
    row = json.loads(result.output)["data"]
    assert result.exit_code == 0 and row["revision"] > first["revision"] and not row["overdue"]
    assert runner.invoke(app, ["--json", *reschedule]).exit_code != 0


def test_durable_auth_refresh_is_bound_and_remembers_access_token(runner, monkeypatch):
    from ksef_client import KsefClientOptions
    from ksef_client import models as m
    from ksef_client.cli.auth import manager
    from ksef_client.cli.auth.scope import login_endpoint, login_scope, token_pair_digest
    from ksef_client.cli.auth.token_cache import get_cached_metadata, set_cached_metadata
    from ksef_client.cli.errors import CliError
    from ksef_client.clients.auth import AuthClient

    options = KsefClientOptions(base_url="https://api-demo.ksef.mf.gov.pl")
    profile = "demo"
    tokens = ("old-access", "old-refresh")

    def persist(_profile, access, refresh):
        nonlocal tokens
        tokens = (access, refresh)

    def refreshed(self, refresh_token):
        assert refresh_token == "old-refresh"
        return m.AuthenticationTokenRefreshResponse(
            m.TokenInfo("fresh-access", "2099-01-01T00:00:00Z")
        )

    monkeypatch.setattr(AuthClient, "refresh_access_token", refreshed)
    monkeypatch.setattr(_workflow, "get_tokens", lambda _: tokens)
    monkeypatch.setattr(manager, "get_tokens", lambda _: tokens)
    monkeypatch.setattr(manager, "save_refreshed_tokens", persist)
    scope = login_scope(options.base_url, "Nip", "123")
    set_cached_metadata(
        profile,
        {
            "login_endpoint": login_endpoint(options.base_url),
            "login_scope": scope,
            "token_pair_digest": token_pair_digest(*tokens),
            "access_valid_until": "2000-01-01T00:00:00Z",
        },
    )
    with pytest.raises(CliError, match="does not match"):
        manager.refresh_access_token(profile=profile, base_url="https://not-the-login.invalid")
    with pytest.raises(CliError, match="HTTPS"):
        _workflow.workflow_client(
            profile, KsefClientOptions("http://example.invalid"), "Nip", "123"
        )
    with _workflow.workflow_client(profile, options, "Nip", "123") as client:
        assert client.api.token_manager.get_access_token() == "fresh-access"
    assert tokens == ("fresh-access", "old-refresh")
    cached = get_cached_metadata(profile)
    assert cached is not None and cached["token_pair_digest"] == token_pair_digest(*tokens)
    assert not manager.save_refreshed_access(
        profile,
        ("old-access", "old-refresh"),
        "must-not-save",
        "",
        expected_scope=scope,
    )
    assert not manager.save_refreshed_access(
        profile, tokens, "must-not-save", "", expected_scope="other"
    )
    with _workflow.workflow_client(profile, options, "Nip", "123") as client:
        assert client.api.token_manager.get_access_token() == "fresh-access"

    # Manual refresh may renew a session created with a context override. The
    # durable workflow still requires the context bound to its own profile.
    override_scope = login_scope(options.base_url, "Nip", "other")
    set_cached_metadata(profile, {**cached, "login_scope": override_scope})
    assert manager.refresh_access_token(profile=profile, base_url=options.base_url)["saved"]
    with pytest.raises(CliError, match="No stored authentication"):
        _workflow.workflow_client(profile, options, "Nip", "123")


@pytest.mark.parametrize("cancelled", [False, True])
def test_offline_cli_retry_requires_authoritative_result(runner, tmp_path, monkeypatch, cancelled):
    from contextlib import nullcontext

    from tests.test_offline_invoice_state import remote_invoice
    from tests.test_offline_invoice_store import DUE, XML
    from tests.test_offline_invoices import TestClient

    from ksef_client import models as m
    from ksef_client.cli.commands import offline_cmd
    from ksef_client.facade import Invoices
    from ksef_client.operations import environment_key

    class RetryClient(TestClient):
        environment = environment_key("https://api-demo.ksef.mf.gov.pl/v2")
        context_key = "Nip:123"

        def __init__(self):
            super().__init__()
            self.invoices = Invoices(cast(Ksef, self))

        def get_session_invoices(self, *args, **kwargs):
            return m.SessionInvoicesResponse([remote_invoice(550)] if cancelled else [])

        def get_session_status(self, reference_number):
            return SimpleNamespace(status=m.StatusInfo(440, ""), invoice_count=0)

    monkeypatch.setenv("KSEF_OFFLINE_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    client = RetryClient()
    monkeypatch.setattr(offline_cmd, "workflow_client", lambda *args: nullcontext(client))
    xml = tmp_path / "invoice.xml"
    xml.write_bytes(XML)
    common = ["--state-dir", str(tmp_path / "private")]
    staged = runner.invoke(
        app, ["--json", "offline", "enqueue", *common, "--xml", str(xml), "--due-at", DUE]
    )
    assert staged.exit_code == 0
    digest = ["--invoice-hash", json.loads(staged.output)["data"]["invoice_hash"]]
    action = "retry-cancelled" if cancelled else "retry-unsubmitted"
    recover = ["--json", "offline", action, *common, *digest]
    assert runner.invoke(app, recover).exit_code != 0
    run = ["--json", "offline", "run", *common, *digest]
    assert runner.invoke(app, run).exit_code == 0
    assert runner.invoke(app, run).exit_code == ExitCode.IO_ERROR
    if cancelled:
        observed = runner.invoke(app, run)
        assert json.loads(observed.output)["data"]["invoices"][0]["status"] == "retryable"
    result = runner.invoke(app, recover)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["data"]["status"] == "queued"
    assert client.send_count == 1


def test_batch_continues_after_an_invoice_error_and_preserves_cursor(runner, tmp_path, monkeypatch):
    from contextlib import nullcontext

    from tests.test_offline_invoice_store import DUE, XML
    from tests.test_offline_invoices import TestClient

    from ksef_client.cli.commands import offline_cmd
    from ksef_client.exceptions import KsefDocumentValidationError
    from ksef_client.facade import Invoices
    from ksef_client.operations import environment_key

    class WorkerClient(TestClient):
        environment = environment_key("https://api-demo.ksef.mf.gov.pl/v2")
        context_key = "Nip:123"

        def __init__(self):
            super().__init__()
            self.invoices = Invoices(cast(Ksef, self))

        def online_session(self):
            if not self.failed_once:
                self.failed_once = True
                raise KsefDocumentValidationError("sensitive invoice details")
            return super().online_session()

    monkeypatch.setenv("KSEF_OFFLINE_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    worker = WorkerClient()
    monkeypatch.setattr(offline_cmd, "workflow_client", lambda *args: nullcontext(worker))
    common = ["--state-dir", str(tmp_path / "private")]
    invoices = []
    for index in range(2):
        xml = tmp_path / f"{index}.xml"
        xml.write_bytes(XML + b" " * index)
        staged = runner.invoke(
            app, ["--json", "offline", "enqueue", *common, "--xml", str(xml), "--due-at", DUE]
        )
        assert staged.exit_code == 0, staged.output
        invoices.append(json.loads(staged.output)["data"]["invoice_hash"])
    first, second = sorted(invoices)
    result = runner.invoke(app, ["--json", "offline", "run", *common, "--limit", "2"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)["data"]
    assert data["failures"][0]["invoice_hash"] == first
    assert data["invoices"][0]["invoice_hash"] == second
    assert data["invoices"][0]["status"] == "session_open"
    assert data["next_cursor"]["invoice_hash"] == second
    assert "sensitive invoice details" not in result.output


@pytest.mark.parametrize("switched", [False, True])
def test_interrupted_refresh_keeps_bound_credentials_usable(runner, monkeypatch, switched):
    from ksef_client import KsefClientOptions
    from ksef_client.cli.auth import manager
    from ksef_client.cli.auth.scope import login_endpoint, login_scope, token_pair_digest
    from ksef_client.cli.auth.token_cache import set_cached_metadata

    options = KsefClientOptions("https://api-demo.ksef.mf.gov.pl")
    tokens = ("old-access", "refresh")
    scope = login_scope(options.base_url, "Nip", "123")
    set_cached_metadata(
        "demo",
        {
            "login_endpoint": login_endpoint(options.base_url),
            "login_scope": scope,
            "token_pair_digest": token_pair_digest(*tokens),
            "access_valid_until": "2099-01-01T00:00:00Z",
        },
    )

    def interrupted(_profile, access, refresh):
        nonlocal tokens
        if switched:
            tokens = (access, refresh)
        raise OSError("Interrupted persistence")

    monkeypatch.setattr(manager, "get_tokens", lambda _: tokens)
    monkeypatch.setattr(_workflow, "get_tokens", lambda _: tokens)
    monkeypatch.setattr(manager, "save_refreshed_tokens", interrupted)
    with pytest.raises(OSError):
        manager.save_refreshed_access(
            "demo", tokens, "new-access", "2099-01-01T00:00:00Z", expected_scope=scope
        )
    with _workflow.workflow_client("demo", options, "Nip", "123") as client:
        assert client.api.token_manager.get_access_token() == (
            "new-access" if switched else "old-access"
        )


@pytest.mark.parametrize(
    "case",
    ["ok", "defaults", "invalid_json", "no_password", "bad_flag", "unavailable", "dependency"],
)
def test_rotated_xades_session_for_durable_commands(runner, tmp_path, monkeypatch, case):
    from contextlib import contextmanager

    from ksef_client import KsefClientOptions
    from ksef_client.cli.errors import CliError

    settings: dict[str, Any] = {}
    opened = []

    class Selector:
        def __init__(self, path, profile, **kwargs):
            settings.update(path=path, profile=profile, **kwargs)

        @contextmanager
        def session(self, *, password_for):
            assert password_for("active-name") == "secret-value"
            try:
                opened.append("open")
                yield "authenticated client"
            finally:
                opened.append("closed")

    def import_rotation(name):
        assert name == "ksef_client.certificate_rotation"
        if case in {"unavailable", "dependency"}:
            raise ModuleNotFoundError(name=name if case == "unavailable" else "xmlsec")
        return SimpleNamespace(ProfileCertificates=Selector)

    monkeypatch.setattr(_workflow, "import_module", import_rotation)
    monkeypatch.setattr(_workflow, "get_tokens", lambda _: pytest.fail("Unexpected token lookup"))
    monkeypatch.setenv("KSEF_XADES_SELECTOR", str(tmp_path / "selector.db"))
    monkeypatch.setenv("KSEF_XADES_CERTIFICATE_DIR", str(tmp_path / "certs"))
    monkeypatch.setenv(
        "KSEF_XADES_KEY_PASSWORDS",
        {"invalid_json": "invalid", "no_password": "{}"}.get(
            case, '{"active-name":"secret-value"}'
        ),
    )
    monkeypatch.setenv("KSEF_XADES_VERIFY_CHAIN", "invalid" if case == "bad_flag" else "true")
    monkeypatch.setenv("KSEF_XADES_ENFORCE_COMPLIANCE", "true")
    options = KsefClientOptions("https://api-demo.ksef.mf.gov.pl")
    if case == "defaults":
        monkeypatch.delenv("KSEF_XADES_VERIFY_CHAIN")
        monkeypatch.delenv("KSEF_XADES_ENFORCE_COMPLIANCE")
    if case not in {"ok", "defaults"}:
        expected_error = ModuleNotFoundError if case == "dependency" else CliError
        with (
            pytest.raises(expected_error),
            _workflow.workflow_client("demo", options, "Nip", "123"),
        ):
            pytest.fail("Unexpected client")
        return
    with _workflow.workflow_client("demo", options, "Nip", "123") as client:
        assert client == "authenticated client"
    assert opened == ["open", "closed"]
    assert settings["profile"].context_value == "123"
    assert settings["store"].require_password
    assert settings["verify_certificate_chain"] is (True if case == "ok" else None)
    assert settings["enforce_xades_compliance"] is (case == "ok")
