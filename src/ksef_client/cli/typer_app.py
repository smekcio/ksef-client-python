from __future__ import annotations

from importlib import metadata

import typer

from .commands import (
    auth_cmd,
    export_cmd,
    health_cmd,
    init_cmd,
    invoice_cmd,
    lighthouse_cmd,
    profile_cmd,
    send_cmd,
    upo_cmd,
)
from .config.loader import load_config
from .context import CliContext

app = typer.Typer(help="KSeF Python CLI - DX-first interface for fast KSeF operations.")


def _version_text() -> str:
    try:
        return metadata.version("ksef-client")
    except Exception:
        return "0.0.0"


def _version_callback(value: bool) -> None:
    if not value:
        return
    typer.echo(f"ksef-cli {_version_text()}")
    raise typer.Exit(0)


@app.callback()
def main(
    ctx: typer.Context,
    profile: str | None = typer.Option(
        None, "--profile", help="Use a specific configured profile."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Render command output as stable JSON envelope."
    ),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (repeatable)."
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors in human output."),
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show CLI version and exit.",
    ),
) -> None:
    _ = version
    config = load_config()
    if profile is not None and profile not in config.profiles:
        raise typer.BadParameter(
            (
                f"Profile '{profile}' does not exist. "
                "Use `ksef profile list` or create it with `ksef profile create`."
            ),
            param_hint="--profile",
        )
    selected_profile = profile
    if selected_profile is None:
        selected_profile = config.active_profile
    ctx.obj = CliContext(
        profile=selected_profile,
        json_output=json_output,
        verbose=verbose,
        no_color=no_color,
    )


app.add_typer(profile_cmd.app, name="profile")
app.add_typer(auth_cmd.app, name="auth")
app.add_typer(health_cmd.app, name="health")
app.add_typer(lighthouse_cmd.app, name="lighthouse")
app.add_typer(invoice_cmd.app, name="invoice")
app.add_typer(send_cmd.app, name="send")
app.add_typer(upo_cmd.app, name="upo")
app.add_typer(export_cmd.app, name="export")
app.command("init")(init_cmd.init_command)


def app_entrypoint() -> None:
    app()
