from __future__ import annotations

from enum import Enum

import typer

from ..config.loader import load_config, save_config
from ..config.profiles import (
    create_profile,
    delete_profile,
    normalize_profile_name,
    require_profile,
    set_active_profile,
    set_profile_value,
)
from ..context import profile_label, require_context
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer

app = typer.Typer(help="Manage CLI profiles.")


class ProfileKey(str, Enum):
    ENV = "env"
    BASE_URL = "base_url"
    CONTEXT_TYPE = "context_type"
    CONTEXT_VALUE = "context_value"


def _render_error(ctx: typer.Context, command: str, exc: Exception) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)

    if isinstance(exc, CliError):
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code=exc.code.name,
            message=exc.message,
            hint=exc.hint,
        )
        raise typer.Exit(int(exc.code))

    renderer.error(
        command=command,
        profile=profile_label(cli_ctx),
        code="UNEXPECTED",
        message=str(exc),
        hint="Run with -v and inspect logs.",
    )
    raise typer.Exit(int(ExitCode.CONFIG_ERROR))


@app.command("list")
def list_profiles(ctx: typer.Context) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    try:
        config = load_config()
        profiles = [
            {
                "name": profile.name,
                "active": profile.name == config.active_profile,
                "env": profile.env or "",
                "base_url": profile.base_url,
                "context_type": profile.context_type,
                "context_value": profile.context_value,
            }
            for profile in config.profiles.values()
        ]
    except Exception as exc:
        _render_error(ctx, "profile.list", exc)
    renderer.success(
        command="profile.list",
        profile=config.active_profile or cli_ctx.profile or profile_label(cli_ctx),
        data={
            "active_profile": config.active_profile or "",
            "count": len(profiles),
            "profiles": profiles,
        },
    )


@app.command("show")
def show_profile(
    ctx: typer.Context,
    name: str | None = typer.Option(
        None, "--name", help="Profile name. Defaults to active profile."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    try:
        config = load_config()
        target_name_raw = name or config.active_profile or cli_ctx.profile
        if target_name_raw is None or target_name_raw.strip() == "":
            raise CliError(
                "No active profile is configured.",
                ExitCode.CONFIG_ERROR,
                "Use --name, `ksef profile use --name <name>`, or `ksef init --set-active`.",
            )
        target_name = normalize_profile_name(target_name_raw)
        profile = require_profile(config, name=target_name)
    except Exception as exc:
        _render_error(ctx, "profile.show", exc)
    renderer.success(
        command="profile.show",
        profile=target_name,
        data={
            "name": profile.name,
            "active": profile.name == config.active_profile,
            "env": profile.env or "",
            "base_url": profile.base_url,
            "context_type": profile.context_type,
            "context_value": profile.context_value,
        },
    )


@app.command("use")
def use_profile(
    ctx: typer.Context, name: str = typer.Option(..., "--name", help="Profile name to activate.")
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    try:
        target_name = normalize_profile_name(name)
        config = load_config()
        set_active_profile(config, name=target_name)
        save_config(config)
    except Exception as exc:
        _render_error(ctx, "profile.use", exc)
    renderer.success(
        command="profile.use",
        profile=target_name,
        data={"active_profile": target_name},
        message="Active profile updated.",
    )


@app.command("create")
def create_profile_command(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", help="Profile name."),
    env: str | None = typer.Option(None, "--env", help="Environment alias: DEMO, TEST or PROD."),
    base_url: str | None = typer.Option(None, "--base-url", help="Explicit base URL override."),
    context_type: str = typer.Option(
        "nip", "--context-type", help="Default context type for auth."
    ),
    context_value: str = typer.Option(
        ..., "--context-value", help="Default context value for auth."
    ),
    set_active: bool = typer.Option(
        False, "--set-active", help="Set this profile as active after creation."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    try:
        profile_name = normalize_profile_name(name)
        config = load_config()
        profile = create_profile(
            config,
            name=profile_name,
            env=env,
            base_url=base_url,
            context_type=context_type,
            context_value=context_value,
        )
        if set_active or config.active_profile is None:
            config.active_profile = profile_name
        save_config(config)
    except Exception as exc:
        _render_error(ctx, "profile.create", exc)
    renderer.success(
        command="profile.create",
        profile=profile_name,
        data={
            "name": profile.name,
            "active_profile": config.active_profile or "",
            "env": profile.env or "",
            "base_url": profile.base_url,
            "context_type": profile.context_type,
            "context_value": profile.context_value,
        },
        message="Profile created.",
    )


@app.command("set")
def set_profile_value_command(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", help="Profile name."),
    key: ProfileKey = typer.Option(..., "--key", case_sensitive=False, help="Field to update."),  # noqa: B008
    value: str = typer.Option(..., "--value", help="New value for selected field."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    try:
        profile_name = normalize_profile_name(name)
        config = load_config()
        updated = set_profile_value(
            config,
            name=profile_name,
            key=key.value,
            value=value,
        )
        save_config(config)
    except Exception as exc:
        _render_error(ctx, "profile.set", exc)
    renderer.success(
        command="profile.set",
        profile=profile_name,
        data={
            "name": updated.name,
            "env": updated.env or "",
            "base_url": updated.base_url,
            "context_type": updated.context_type,
            "context_value": updated.context_value,
        },
        message="Profile updated.",
    )


@app.command("delete")
def delete_profile_command(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", help="Profile name to delete."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    try:
        profile_name = normalize_profile_name(name)
        config = load_config()
        delete_profile(config, name=profile_name)
        save_config(config)
    except Exception as exc:
        _render_error(ctx, "profile.delete", exc)
    renderer.success(
        command="profile.delete",
        profile=config.active_profile or cli_ctx.profile or profile_label(cli_ctx),
        data={
            "deleted_profile": profile_name,
            "active_profile": config.active_profile or "",
        },
        message="Profile deleted.",
    )
