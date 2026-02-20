import pytest
import typer
from click import Command

from ksef_client.cli.context import CliContext, profile_label, require_context, require_profile
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_context_defaults() -> None:
    ctx = CliContext(profile="demo", json_output=False, verbose=0, no_color=False)
    assert ctx.profile == "demo"


def test_require_context_raises_for_missing_obj() -> None:
    ctx = typer.Context(Command("ctx"))
    with pytest.raises(typer.BadParameter):
        require_context(ctx)


def test_require_profile_returns_profile_when_set() -> None:
    ctx = CliContext(profile=" demo ", json_output=False, verbose=0, no_color=False)
    assert require_profile(ctx) == "demo"


def test_require_profile_raises_config_error_when_missing() -> None:
    ctx = CliContext(profile=None, json_output=False, verbose=0, no_color=False)
    with pytest.raises(CliError) as exc:
        require_profile(ctx)
    assert exc.value.code == ExitCode.CONFIG_ERROR
    assert "No active profile is configured." in exc.value.message


def test_profile_label_for_unconfigured_context() -> None:
    ctx = CliContext(profile=None, json_output=False, verbose=0, no_color=False)
    assert profile_label(ctx) == "<unconfigured>"
