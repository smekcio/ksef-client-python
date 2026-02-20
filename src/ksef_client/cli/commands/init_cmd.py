from __future__ import annotations

import typer

from ..config.loader import load_config, save_config
from ..config.profiles import normalize_profile_name, upsert_profile
from ..constants import DEFAULT_PROFILE
from ..context import require_context
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer


def _require_non_empty(value: str | None, *, option_name: str) -> str:
    if value is None or value.strip() == "":
        raise CliError(
            f"Missing value for {option_name}.",
            ExitCode.VALIDATION_ERROR,
            "Provide all required onboarding inputs.",
        )
    return value.strip()


def _render_error(ctx: typer.Context, command: str, exc: Exception) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)

    if isinstance(exc, CliError):
        renderer.error(
            command=command,
            profile=cli_ctx.profile or DEFAULT_PROFILE,
            code=exc.code.name,
            message=exc.message,
            hint=exc.hint,
        )
        raise typer.Exit(int(exc.code))

    renderer.error(
        command=command,
        profile=cli_ctx.profile or DEFAULT_PROFILE,
        code="UNEXPECTED",
        message=str(exc),
        hint="Run with -v and inspect logs.",
    )
    raise typer.Exit(int(ExitCode.CONFIG_ERROR))


def init_command(
    ctx: typer.Context,
    name: str | None = typer.Option(None, "--name", help="Profile name to create or update."),
    env: str | None = typer.Option(None, "--env", help="Environment alias: DEMO, TEST or PROD."),
    base_url: str | None = typer.Option(None, "--base-url", help="Explicit base URL override."),
    context_type: str | None = typer.Option(
        None, "--context-type", help="Default context type for auth."
    ),
    context_value: str | None = typer.Option(
        None, "--context-value", help="Default context value for auth."
    ),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", help="Require all inputs via options."
    ),
    set_active: bool = typer.Option(
        False, "--set-active", help="Set created/updated profile as active."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)

    try:
        default_name = normalize_profile_name(name or cli_ctx.profile or DEFAULT_PROFILE)
        profile_name = normalize_profile_name(
            default_name if non_interactive else typer.prompt("Profile name", default=default_name)
        )

        selected_env = env
        selected_base_url = base_url
        selected_context_type = context_type
        selected_context_value = context_value

        if not non_interactive:
            if selected_env is None and selected_base_url is None:
                selected_env = typer.prompt("Environment [DEMO/TEST/PROD]", default="DEMO")
            if selected_base_url is None:
                selected_base_url = typer.prompt("Base URL", default="")
            if selected_context_type is None:
                selected_context_type = typer.prompt("Context type", default="nip")
            if selected_context_value is None:
                selected_context_value = typer.prompt("Context value (e.g. NIP)")

        safe_context_type = _require_non_empty(selected_context_type, option_name="--context-type")
        safe_context_value = _require_non_empty(
            selected_context_value, option_name="--context-value"
        )

        config = load_config()
        profile, existed = upsert_profile(
            config,
            name=profile_name,
            env=selected_env,
            base_url=selected_base_url,
            context_type=safe_context_type,
            context_value=safe_context_value,
        )
        if set_active or config.active_profile is None:
            config.active_profile = profile_name
        save_config(config)

    except Exception as exc:
        _render_error(ctx, "init", exc)

    renderer.success(
        command="init",
        profile=profile_name,
        data={
            "profile": profile.name,
            "active_profile": config.active_profile or "",
            "env": profile.env or "",
            "base_url": profile.base_url,
            "context_type": profile.context_type,
            "context_value": profile.context_value,
            "updated_existing": str(existed).lower(),
        },
        message="CLI initialized and profile saved.",
    )
