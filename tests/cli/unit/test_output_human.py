from ksef_client.cli.output.human import HumanRenderer


def test_human_renderer_smoke() -> None:
    renderer = HumanRenderer(no_color=True)
    renderer.info("ok", command="test")


def test_human_renderer_invoice_list_table(capsys) -> None:
    renderer = HumanRenderer(no_color=True)
    renderer.success(
        command="invoice.list",
        profile="demo",
        data={
            "count": 1,
            "from": "2026-01-01T00:00:00Z",
            "to": "2026-01-31T23:59:59Z",
            "items": [
                {
                    "ksefNumber": "KSEF-1",
                    "invoiceNumber": "FV/1/2026",
                    "issueDate": "2026-01-10",
                    "grossAmount": 123.45,
                }
            ],
            "continuation_token": "",
        },
    )
    out = capsys.readouterr().out
    assert "Invoices" in out
    assert "KSEF-1" in out
    assert "count" in out


def test_human_renderer_invoice_list_fallback_and_non_dict_items(capsys) -> None:
    renderer = HumanRenderer(no_color=True)
    renderer.success(
        command="invoice.list",
        profile="demo",
        data={"count": 0, "items": []},
    )
    renderer.success(
        command="invoice.list",
        profile="demo",
        data={"count": 1, "items": ["not-dict", {"ksefNumber": "KSEF-2"}]},
    )
    out = capsys.readouterr().out
    assert "- count: 0" in out
    assert "KSEF-2" in out


def test_human_renderer_success_skips_raw_response_payload(capsys) -> None:
    renderer = HumanRenderer(no_color=True)
    renderer.success(
        command="send.status",
        profile="demo",
        data={"status_code": 200, "response": {"raw": "payload"}},
    )
    out = capsys.readouterr().out
    assert "status_code: 200" in out
    assert "raw" not in out


def test_human_renderer_success_without_data(capsys) -> None:
    renderer = HumanRenderer(no_color=True)
    renderer.success(command="send.status", profile="demo", data=None)
    out = capsys.readouterr().out
    assert "OK" in out
    assert "send.status" in out


def test_human_renderer_error_prints_hint(capsys) -> None:
    renderer = HumanRenderer(no_color=True)
    renderer.error(
        command="auth.login-token",
        profile="demo",
        code="AUTH_ERROR",
        message="Missing token",
        hint="Run ksef auth login-token",
    )
    out = capsys.readouterr().out
    assert "AUTH_ERROR" in out
    assert "Hint: Run ksef auth login-token" in out
