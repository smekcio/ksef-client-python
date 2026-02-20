from ksef_client.cli.app import app
from ksef_client.cli.auth.keyring_store import clear_tokens
from ksef_client.cli.exit_codes import ExitCode


def test_minimal_smoke_flow(runner) -> None:
    clear_tokens("demo")
    assert runner.invoke(app, ["--help"]).exit_code == 0
    assert runner.invoke(app, ["auth", "status"]).exit_code == 0
    assert runner.invoke(app, ["invoice", "list"]).exit_code == int(ExitCode.AUTH_ERROR)
