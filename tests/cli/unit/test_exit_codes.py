from ksef_client.cli.exit_codes import ExitCode


def test_exit_codes_are_stable() -> None:
    assert ExitCode.SUCCESS == 0
    assert ExitCode.VALIDATION_ERROR == 2
    assert ExitCode.AUTH_ERROR == 3
    assert ExitCode.RETRY_EXHAUSTED == 4
    assert ExitCode.API_ERROR == 5
    assert ExitCode.CONFIG_ERROR == 6
    assert ExitCode.CIRCUIT_OPEN == 7
    assert ExitCode.IO_ERROR == 8
