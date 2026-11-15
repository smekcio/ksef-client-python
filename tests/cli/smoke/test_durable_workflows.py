import base64
import json
from types import SimpleNamespace
from typing import cast

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
    assert json.loads(status.output)["data"]["status"] == "uninitialized"
    sync = ["--json", "archive", "sync", *common, "--since", START, "--until", END]
    first = runner.invoke(app, [*sync, "--max-documents", "1"])
    assert first.exit_code == 0, first.output
    assert json.loads(first.output)["data"]["status"] == "importing"
    status = runner.invoke(app, ["--json", "archive", "status", *common])
    assert status.exit_code == 0, status.output
    assert json.loads(status.output)["data"]["committed_hwm"] is None
    second = runner.invoke(app, sync)
    assert second.exit_code == 0, second.output
    status = runner.invoke(app, ["--json", "archive", "status", *common])
    assert json.loads(status.output)["data"]["committed_hwm"] == END
    assert client.downloads == len(client.requests) == 1


def test_offline_run_reconciles_lost_send_and_honors_429(runner, tmp_path, monkeypatch):
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
                raise KsefRateLimitError(429, "rate limited", retry_after=17)
            return super().online_session()

    monkeypatch.setenv("KSEF_OFFLINE_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    client = OfflineClient()
    monkeypatch.setattr(offline_cmd, "workflow_client", lambda *args: nullcontext(client))
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
    assert json.loads(limited.output)["errors"][0]["retry_after_seconds"] == 17

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

    assert json.loads(runner.invoke(app, run).output)["data"]["invoices"][0]["status"] == "accepted"
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
