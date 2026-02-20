from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_cli_error_mapping() -> None:
    error = CliError("x", ExitCode.API_ERROR, hint="h")
    assert "Hint" in str(error)
    assert str(CliError("plain", ExitCode.API_ERROR)) == "plain"
