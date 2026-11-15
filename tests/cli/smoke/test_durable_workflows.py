import base64
import json

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
            self.exports.sync_archive = Exports(self).sync_archive

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
