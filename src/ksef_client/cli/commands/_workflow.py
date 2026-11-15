from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import typer

from ksef_client import AuthenticatedClient, Ksef, KsefClientOptions
from ksef_client.exceptions import KsefError, KsefRateLimitError
from ksef_client.facade import connection_options
from ksef_client.models import TokenInfo
from ksef_client.offline_invoices import SQLiteOfflineInvoiceStore
from ksef_client.operations import environment_key
from ksef_client.profiles import ProfileStore
from ksef_client.retry import parse_retry_after_seconds
from ksef_client.token_manager import TokenManager

from ..auth.keyring_store import get_tokens
from ..auth.manager import save_refreshed_access
from ..auth.scope import login_scope, token_pair_digest
from ..auth.token_cache import auth_state_lock, get_cached_metadata
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode, exit_code_for_error
from ..output import get_renderer
from ._error_utils import build_rate_limit_hint


def workflow_config(
    ctx: typer.Context, root: Path
) -> tuple[str, KsefClientOptions, str, str, Path]:
    profile = require_profile(require_context(ctx))
    options, kind, context = connection_options(
        profile=profile, profile_store=ProfileStore.default()
    )
    identity = json.dumps(
        [profile, environment_key(options.normalized_base_url()), kind, context],
        separators=(",", ":"),
    ).encode()
    directory = root.absolute() / hashlib.sha256(identity).hexdigest()
    return profile, options, kind, context, directory


def workflow_key(variable: str) -> bytes:
    try:
        key = base64.b64decode(os.environ.get(variable, ""), validate=True)
    except ValueError:
        key = b""
    if len(key) != 32:
        raise CliError(
            f"{variable} must contain a Base64-encoded 32-byte key.",
            ExitCode.CONFIG_ERROR,
            "Load the same key from the secret store on each run.",
        )
    return key


def workflow_client(profile: str, options: KsefClientOptions, kind: str, context: str) -> Ksef:
    endpoint = urlsplit(options.normalized_base_url())
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.username is not None
        or endpoint.query
        or endpoint.fragment
    ):
        raise CliError("A fixed HTTPS API endpoint is required.", ExitCode.CONFIG_ERROR)
    scope = login_scope(options.base_url, kind, context)
    with auth_state_lock(profile):
        tokens = get_tokens(profile)
        metadata = get_cached_metadata(profile) or {}
    if (
        not tokens
        or metadata.get("login_scope") != scope
        or metadata.get("token_pair_digest") != token_pair_digest(*tokens)
    ):
        raise CliError(
            "No stored authentication bound to this profile and context.",
            ExitCode.AUTH_ERROR,
            "Log in again with ksef auth login-xades or ksef auth login-token.",
        )
    expected_tokens = tokens

    def persist(info: TokenInfo) -> None:
        nonlocal expected_tokens
        if save_refreshed_access(
            profile, expected_tokens, info.token, info.valid_until or "", expected_scope=scope
        ):
            expected_tokens = info.token, expected_tokens[1]

    manager = TokenManager(
        *tokens,
        access_token_valid_until=metadata.get("access_valid_until") or None,
        on_refresh=persist,
    )
    return Ksef(
        AuthenticatedClient(options, manager), options, context_type=kind, context_value=context
    )


@contextmanager
def offline_store(directory: Path, *, create: bool = False) -> Iterator[SQLiteOfflineInvoiceStore]:
    key = workflow_key("KSEF_OFFLINE_STATE_KEY")
    path = directory / "offline.db"
    if not create and not path.is_file():
        raise CliError("The offline queue has not been created.", ExitCode.CONFIG_ERROR)
    with SQLiteOfflineInvoiceStore.open(path, key=key) as store:
        yield store


@contextmanager
def workflow_errors(ctx: typer.Context, command: str) -> Iterator[None]:
    try:
        yield
    except (CliError, KsefError, ValueError, OSError, sqlite3.Error) as exc:
        hint = None
        retry_after_seconds = None
        if isinstance(exc, CliError):
            code, message, hint = exc.code, exc.message, exc.hint
        elif isinstance(exc, KsefRateLimitError):
            code, message = ExitCode.RETRY_EXHAUSTED, "KSeF rate limit reached."
            hint = build_rate_limit_hint(exc, default_hint="Wait before the next cycle.")
            retry_after_seconds = (
                float(exc.retry_after)
                if exc.retry_after is not None
                else parse_retry_after_seconds(exc.retry_after_raw)
            )
        elif isinstance(exc, KsefError):
            code = exit_code_for_error(exc) or ExitCode.API_ERROR
            message = "The KSeF workflow failed. Inspect the saved state before retrying."
        elif isinstance(exc, (OSError, sqlite3.Error)):
            code, message = ExitCode.IO_ERROR, "Could not read or write the workflow files."
        else:
            code, message = ExitCode.VALIDATION_ERROR, str(exc)
        cli_ctx = require_context(ctx)
        get_renderer(cli_ctx).error(
            command=command,
            profile=profile_label(cli_ctx),
            code=code.name,
            message=message,
            hint=hint,
            retry_after_seconds=retry_after_seconds,
        )
        raise typer.Exit(int(code)) from exc
