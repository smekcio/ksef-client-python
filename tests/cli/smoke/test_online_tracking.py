import base64
import json
from contextlib import nullcontext
from typing import cast

import pytest
from tests.test_offline_invoice_state import NUMBER, remote_invoice
from tests.test_offline_invoice_store import KEY, XML
from tests.test_online_invoices import Server

from ksef_client import Ksef, KsefClientOptions
from ksef_client.cli import app
from ksef_client.cli.commands import online_cmd
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.exceptions import KsefRateLimitError
from ksef_client.facade import Invoices
from ksef_client.operations import environment_key
from ksef_client.profiles import ProfileStore


@pytest.fixture
def online(runner, tmp_path, monkeypatch):
    server = Server()
    options = KsefClientOptions("https://api-demo.ksef.mf.gov.pl")
    server.options = server._http._options = options
    server._http.api_base_url = options.normalized_base_url()
    server.environment = environment_key(options.normalized_base_url())
    server.context_key = "Nip:123"
    server.invoices = Invoices(cast(Ksef, server))  # type: ignore[attr-defined]
    monkeypatch.setenv("KSEF_ONLINE_STATE_KEY", base64.b64encode(KEY).decode())
    monkeypatch.setattr(online_cmd, "workflow_client", lambda *args: nullcontext(server))
    monkeypatch.setattr(online_cmd, "wait_seconds", lambda _: None)
    state_dir = str(tmp_path / "private")
    xml = tmp_path / "invoice.xml"
    xml.write_bytes(XML)

    def command(*args, code=0, human=False, profile="demo"):
        result = runner.invoke(app, ["--profile", profile, *([] if human else ["--json"]), *args])
        assert result.exit_code == code, (result.output, result.exception)
        if human:
            return result.output
        payload = json.loads(result.output)
        assert payload["ok"] is (code == 0)
        return payload["data"] if code == 0 else payload["errors"][0]

    return server, command, state_dir, str(xml)


def test_recovers_lost_send_with_same_id_and_saves_individual_upo(online, tmp_path):
    server, invoke, root, xml = online
    local_id = "[red]FV-001"
    item = ["--id", local_id, "--state-dir", root]
    send = ["send", "online", "--local-id", local_id, "--state-dir", root, "--invoice", xml]
    invoke(*send, code=ExitCode.IO_ERROR)
    assert invoke("online", "status", *item)["status"] == "submission_unknown"
    assert invoke(*send)["status"] == "submission_unknown"
    assert server.send_count == 1
    server.result = remote_invoice(200, number=NUMBER)
    assert invoke("online", "run", *item)["ksef_number"] == NUMBER
    invoke("online", "run", *item, code=ExitCode.IO_ERROR)  # close response lost
    assert invoke("online", "run", *item)["status"] == "complete"
    out = tmp_path / "proof.xml"
    invoke("online", "upo", *item, "--out", str(out))
    assert out.read_bytes() == server.upo
    invoke("online", "upo", *item, "--out", str(out), code=ExitCode.IO_ERROR)
    assert local_id in invoke("online", "status", *item, human=True)
    assert server.open_count == server.send_count == server.close_count == 1
    assert invoke(*send, "--wait-upo", "--save-upo", str(out), "--save-upo-overwrite")[
        "upo_path"
    ] == str(out)


def test_enqueue_and_reads_are_local_and_scoped(online, tmp_path, monkeypatch):
    _, invoke, root, xml = online
    monkeypatch.setattr(
        online_cmd, "workflow_client", lambda *args: pytest.fail("unexpected login")
    )
    item = ["--id", "A", "--state-dir", root]
    invoke("online", "status", *item, code=ExitCode.CONFIG_ERROR)
    assert invoke("online", "enqueue", *item, "--xml", xml)["status"] == "queued"
    assert invoke("online", "enqueue", *item, "--xml", xml)["revision"] == 1
    invoke(
        "online",
        "enqueue",
        "--id",
        "B",
        "--state-dir",
        root,
        "--xml",
        xml,
        code=ExitCode.VALIDATION_ERROR,
    )
    invoke("online", "status", "--id", "B", "--state-dir", root, code=ExitCode.VALIDATION_ERROR)
    invoke(
        "online",
        "upo",
        *item,
        "--out",
        str(tmp_path / "pending.xml"),
        code=ExitCode.VALIDATION_ERROR,
    )
    assert not (tmp_path / "pending.xml").exists()
    ProfileStore.default().create("other", env="DEMO", context_type="nip", context_value="456")
    invoke("online", "status", *item, profile="other", code=ExitCode.CONFIG_ERROR)
    monkeypatch.setenv("KSEF_ONLINE_STATE_KEY", base64.b64encode(b"X" * 32).decode())
    invoke("online", "status", *item, code=ExitCode.VALIDATION_ERROR)


def test_wait_polling_timeout_rejection_and_explicit_requeue(online):
    server, invoke, root, xml = online
    server.lose_send = False
    send = ["send", "online", "--local-id", "A", "--state-dir", root, "--invoice", xml]
    item = ["--id", "A", "--state-dir", root]
    assert invoke(*send)["status"] == "submitted"
    server.result = remote_invoice(150)
    assert (
        invoke(*send, "--wait-status", "--max-attempts", "2", code=ExitCode.RETRY_EXHAUSTED)["code"]
        == "RETRY_EXHAUSTED"
    )
    server.result = remote_invoice(550)
    invoke(
        *send, "--wait-upo", code=ExitCode.IO_ERROR
    )  # close was applied but its response was lost
    invoke(*send, "--wait-upo", code=ExitCode.API_ERROR)
    assert invoke("online", "status", *item)["status"] == "retryable"
    assert invoke("online", "retry-cancelled", *item)["status"] == "queued"
    assert server.send_count == 1


def test_repeat_send_uses_local_result_and_wait_upo_saves_verified_document(
    online, tmp_path, monkeypatch
):
    server, invoke, root, xml = online
    server.lose_send = False
    send = ["send", "online", "--local-id", "A", "--state-dir", root, "--invoice", xml]
    row = invoke(*send)
    assert (row["session_ref"], row["invoice_ref"], row["status"]) == (
        "session-1",
        "invoice-1",
        "submitted",
    )
    with monkeypatch.context() as patch:
        patch.setattr(online_cmd, "workflow_client", lambda *args: pytest.fail("unexpected login"))
        assert invoke(*send) == row

    def close(reference):
        assert reference == "session-1"
        server.close_count += 1

    monkeypatch.setattr(server, "close_online_session", close)
    server.result = remote_invoice(200, number=NUMBER)
    out = tmp_path / "upo" / "proof.xml"
    result = invoke(*send, "--wait-upo", "--save-upo", str(out))
    assert (result["status"], result["upo_path"], result["ksef_number"]) == (
        "complete",
        str(out),
        NUMBER,
    )
    assert out.read_bytes() == server.upo
    assert server.send_count == server.open_count == server.close_count == 1


def test_unsubmitted_retry_delegates_to_remote_evidence(online):
    server, invoke, root, xml = online
    item = ["--id", "A", "--state-dir", root]
    invoke(
        "send",
        "online",
        "--invoice",
        xml,
        "--local-id",
        "A",
        "--state-dir",
        root,
        code=ExitCode.IO_ERROR,
    )
    server.session_code = 440
    server.successful_invoice_count = server.failed_invoice_count = 0
    assert invoke("online", "retry-unsubmitted", *item)["status"] == "queued"
    assert server.send_count == 1


def test_status_rate_limit_preserves_retry_interval_and_does_not_resubmit(online, monkeypatch):
    server, invoke, root, xml = online
    server.lose_send = False
    send = ["send", "online", "--local-id", "A", "--state-dir", root, "--invoice", xml]
    assert invoke(*send)["status"] == "submitted"

    def throttled(*args):
        raise KsefRateLimitError(429, "too many requests", retry_after_raw="90")

    with monkeypatch.context() as patch:
        patch.setattr(server, "get_session_invoice_status", throttled)
        error = invoke(*send, "--wait-status", code=ExitCode.RETRY_EXHAUSTED)
        assert error["retry_after_seconds"] == 90
    server.result = remote_invoice(200, number=NUMBER)
    assert invoke(*send, "--wait-status")["status"] == "accepted"
    assert server.send_count == server.open_count == 1


@pytest.mark.parametrize(
    "flags",
    [
        ["--local-id", "A"],
        ["--state-dir", "work"],
        ["--local-id", "A", "--state-dir", "work", "--upo-v43"],
        ["--local-id", "A", "--state-dir", "work", "--save-upo", "upo.xml"],
        ["--local-id", "A", "--state-dir", "work", "--wait-upo", "--poll-interval", "nan"],
    ],
)
def test_invalid_tracking_options_fail_before_writes(runner, tmp_path, flags):
    result = runner.invoke(
        app, ["--json", "send", "online", "--invoice", str(tmp_path / "absent.xml"), *flags]
    )
    assert result.exit_code == ExitCode.VALIDATION_ERROR, result.output
