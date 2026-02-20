from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import typer

from .errors import CliError
from .exit_codes import ExitCode

_UNCONFIGURED_PROFILE = "<unconfigured>"


@dataclass
class CliContext:
    profile: str | None
    json_output: bool
    verbose: int
    no_color: bool
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def require_context(ctx: typer.Context) -> CliContext:
    if not isinstance(ctx.obj, CliContext):
        raise typer.BadParameter("CLI context is not initialized.")
    return ctx.obj


def profile_label(cli_ctx: CliContext) -> str:
    return cli_ctx.profile or _UNCONFIGURED_PROFILE


def require_profile(cli_ctx: CliContext) -> str:
    if cli_ctx.profile is not None and cli_ctx.profile.strip() != "":
        return cli_ctx.profile.strip()
    raise CliError(
        "No active profile is configured.",
        ExitCode.CONFIG_ERROR,
        "Run `ksef init --set-active`, `ksef profile use --name <name>`, or pass `--profile`.",
    )
