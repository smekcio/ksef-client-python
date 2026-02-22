from __future__ import annotations

import os
import sys

from click.core import ParameterSource
import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError

from ..auth.manager import (
    get_auth_status,
    login_with_token,
    login_with_xades,
    logout,
    refresh_access_token,
    resolve_base_url,
)
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer

app = typer.Typer(help="Authenticate and manage tokens.")


def _is_interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _warn_if_secret_from_cli(
    *,
    ctx: typer.Context,
    renderer,
    command: str,
    parameter_name: str,
    option_name: str,
    value: str | None,
) -> None:
    if value is None:
        return
    try:
        source = ctx.get_parameter_source(parameter_name)
    except Exception:
        return
    if source != ParameterSource.COMMANDLINE:
        return
    renderer.info(
        (
            f"WARNING: Secret provided via {option_name}. "
            "This may be visible in shell history/process lists. "
            f"Prefer omitting {option_name} for hidden prompt input."
        ),
        command=command,
    )


def _prompt_required_secret(secret: str | None, *, prompt: str) -> str | None:
    if secret is not None:
        return secret
    if not _is_interactive_terminal():
        return None
    return typer.prompt(prompt, hide_input=True)


def _prompt_optional_secret(secret: str | None, *, prompt: str) -> str | None:
    if secret is not None:
        return secret
    if not _is_interactive_terminal():
        return None
    value = typer.prompt(
        f"{prompt} (leave empty if not set)",
        hide_input=True,
        default="",
        show_default=False,
    )
    return value or None


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

    if isinstance(exc, KsefRateLimitError):
        hint = f"Retry-After: {exc.retry_after}" if exc.retry_after else "Wait and retry."
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code="RATE_LIMIT",
            message=str(exc),
            hint=hint,
        )
        raise typer.Exit(int(ExitCode.RETRY_EXHAUSTED))

    if isinstance(exc, KsefApiError):
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code="API_ERROR",
            message=str(exc),
            hint="Inspect response details and verify input data.",
        )
        raise typer.Exit(int(ExitCode.API_ERROR))

    if isinstance(exc, KsefHttpError):
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code="HTTP_ERROR",
            message=str(exc),
            hint="Check network connectivity and KSeF endpoint.",
        )
        raise typer.Exit(int(ExitCode.API_ERROR))

    renderer.error(
        command=command,
        profile=profile_label(cli_ctx),
        code="UNEXPECTED",
        message=str(exc),
        hint="Run with -v and check stack trace in logs.",
    )
    raise typer.Exit(int(ExitCode.CONFIG_ERROR))


@app.command("login-token")
def login_token(
    ctx: typer.Context,
    ksef_token: str | None = typer.Option(
        None,
        "--ksef-token",
        help=(
            "KSeF system token. If omitted, uses KSEF_TOKEN env var "
            "or hidden prompt input in interactive mode."
        ),
    ),
    context_type: str | None = typer.Option(
        None,
        "--context-type",
        help="Context identifier type, e.g. nip. Fallback: KSEF_CONTEXT_TYPE/profile context.",
    ),
    context_value: str | None = typer.Option(
        None,
        "--context-value",
        help="Context identifier value. Fallback: KSEF_CONTEXT_VALUE/profile context.",
    ),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Polling interval in seconds."
    ),
    max_attempts: int = typer.Option(90, "--max-attempts", help="Maximum polling attempts."),
    save: bool = typer.Option(
        True, "--save/--no-save", help="Persist received tokens in configured token store."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    token = ksef_token if ksef_token is not None else os.getenv("KSEF_TOKEN")
    token = _prompt_required_secret(token, prompt="KSeF token")
    _warn_if_secret_from_cli(
        ctx=ctx,
        renderer=renderer,
        command="auth.login-token",
        parameter_name="ksef_token",
        option_name="--ksef-token",
        value=ksef_token,
    )
    try:
        profile = require_profile(cli_ctx)
        result = login_with_token(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            token=token,
            context_type=context_type or os.getenv("KSEF_CONTEXT_TYPE", ""),
            context_value=context_value or os.getenv("KSEF_CONTEXT_VALUE", ""),
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            save=save,
        )
    except Exception as exc:
        _render_error(ctx, "auth.login-token", exc)
    renderer.success(
        command="auth.login-token",
        profile=profile,
        data=result,
        message="Authentication successful.",
    )


@app.command("login-xades")
def login_xades(
    ctx: typer.Context,
    pkcs12_path: str | None = typer.Option(
        None,
        "--pkcs12-path",
        help="Path to PKCS#12 file for XAdES authentication.",
    ),
    pkcs12_password: str | None = typer.Option(
        None,
        "--pkcs12-password",
        help="Password for PKCS#12 file. Omit to enter securely via hidden prompt.",
    ),
    cert_pem: str | None = typer.Option(None, "--cert-pem", help="Path to certificate PEM file."),
    key_pem: str | None = typer.Option(None, "--key-pem", help="Path to private key PEM file."),
    key_password: str | None = typer.Option(
        None,
        "--key-password",
        help="Password for private key PEM. Omit to enter securely via hidden prompt.",
    ),
    context_type: str | None = typer.Option(
        None,
        "--context-type",
        help="Context identifier type, e.g. nip. Fallback: KSEF_CONTEXT_TYPE/profile context.",
    ),
    context_value: str | None = typer.Option(
        None,
        "--context-value",
        help="Context identifier value. Fallback: KSEF_CONTEXT_VALUE/profile context.",
    ),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
    subject_identifier_type: str = typer.Option(
        "certificateSubject",
        "--subject-identifier-type",
        help="Subject type: certificateSubject or certificateFingerprint.",
    ),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Polling interval in seconds."
    ),
    max_attempts: int = typer.Option(90, "--max-attempts", help="Maximum polling attempts."),
    save: bool = typer.Option(
        True, "--save/--no-save", help="Persist received tokens in configured token store."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    use_pkcs12 = bool(pkcs12_path and pkcs12_path.strip())
    use_pem_pair = bool((cert_pem and cert_pem.strip()) or (key_pem and key_pem.strip()))
    resolved_pkcs12_password = pkcs12_password
    resolved_key_password = key_password
    if use_pkcs12:
        resolved_pkcs12_password = _prompt_optional_secret(
            pkcs12_password, prompt="PKCS#12 password"
        )
    if use_pem_pair:
        resolved_key_password = _prompt_optional_secret(key_password, prompt="Private key password")
    _warn_if_secret_from_cli(
        ctx=ctx,
        renderer=renderer,
        command="auth.login-xades",
        parameter_name="pkcs12_password",
        option_name="--pkcs12-password",
        value=pkcs12_password,
    )
    _warn_if_secret_from_cli(
        ctx=ctx,
        renderer=renderer,
        command="auth.login-xades",
        parameter_name="key_password",
        option_name="--key-password",
        value=key_password,
    )
    try:
        profile = require_profile(cli_ctx)
        result = login_with_xades(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            context_type=context_type or os.getenv("KSEF_CONTEXT_TYPE", ""),
            context_value=context_value or os.getenv("KSEF_CONTEXT_VALUE", ""),
            pkcs12_path=pkcs12_path,
            pkcs12_password=resolved_pkcs12_password,
            cert_pem=cert_pem,
            key_pem=key_pem,
            key_password=resolved_key_password,
            subject_identifier_type=subject_identifier_type,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            save=save,
        )
    except Exception as exc:
        _render_error(ctx, "auth.login-xades", exc)
    renderer.success(
        command="auth.login-xades",
        profile=profile,
        data=result,
        message="Authentication successful.",
    )


@app.command("status")
def auth_status(ctx: typer.Context) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = get_auth_status(profile)
    except Exception as exc:
        _render_error(ctx, "auth.status", exc)
    renderer.success(
        command="auth.status",
        profile=profile,
        data=result,
    )


@app.command("refresh")
def auth_refresh(
    ctx: typer.Context,
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
    save: bool = typer.Option(True, "--save/--no-save", help="Persist refreshed access token."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = refresh_access_token(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            save=save,
        )
    except Exception as exc:
        _render_error(ctx, "auth.refresh", exc)
    renderer.success(
        command="auth.refresh",
        profile=profile,
        data=result,
        message="Access token refreshed.",
    )


@app.command("logout")
def auth_logout(ctx: typer.Context) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = logout(profile)
    except Exception as exc:
        _render_error(ctx, "auth.logout", exc)
    renderer.success(
        command="auth.logout",
        profile=profile,
        data=result,
        message="Stored tokens removed.",
    )
