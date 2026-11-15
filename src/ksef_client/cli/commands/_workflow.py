from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from importlib import import_module
from pathlib import Path
from urllib.parse import urlsplit

import typer

from ksef_client import AuthenticatedClient, Ksef, KsefClientOptions
from ksef_client.certificates import FileCertificateStore
from ksef_client.exceptions import KsefError, KsefRateLimitError
from ksef_client.facade import connection_options
from ksef_client.models import TokenInfo
from ksef_client.offline_invoices import SQLiteOfflineInvoiceStore
from ksef_client.operations import environment_key
from ksef_client.profiles import Profile, ProfileStore
from ksef_client.retry import parse_retry_after_seconds
from ksef_client.token_manager import TokenManager

from ..auth.keyring_store import get_tokens
from ..auth.manager import save_refreshed_access
from ..auth.scope import login_scope, recover_refreshed_metadata, token_pair_digest
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


def _xades_flag(name: str) -> bool | None:
    value = os.environ.get(name)
    if value is None:
        return None
    if value not in {"true", "false"}:
        raise CliError(f"{name} must be true or false.", ExitCode.CONFIG_ERROR)
    return value == "true"


def _xades_workflow_client(path: str, profile: Profile) -> AbstractContextManager[Ksef]:
    try:
        rotation = import_module("ksef_client.certificate_rotation")
    except ModuleNotFoundError as exc:
        if exc.name != "ksef_client.certificate_rotation":
            raise
        raise CliError(
            "XAdES certificate rotation is unavailable.", ExitCode.CONFIG_ERROR
        ) from None

    try:
        passwords = json.loads(os.environ.get("KSEF_XADES_KEY_PASSWORDS", "{}"))
    except ValueError:
        raise CliError("Invalid XAdES password configuration.", ExitCode.CONFIG_ERROR) from None

    def password_for(name: str) -> str:
        password = passwords.get(name) if isinstance(passwords, dict) else None
        if not isinstance(password, str) or not password:
            raise CliError("No password for the active XAdES certificate.", ExitCode.CONFIG_ERROR)
        return password

    store = FileCertificateStore(
        os.environ.get("KSEF_XADES_CERTIFICATE_DIR"), require_password=True
    )
    selector = rotation.ProfileCertificates(
        path,
        profile,
        store=store,
        verify_certificate_chain=_xades_flag("KSEF_XADES_VERIFY_CHAIN"),
        enforce_xades_compliance=bool(_xades_flag("KSEF_XADES_ENFORCE_COMPLIANCE")),
    )
    session: AbstractContextManager[Ksef] = selector.session(password_for=password_for)
    return session


def workflow_client(
    profile: str, options: KsefClientOptions, kind: str, context: str
) -> AbstractContextManager[Ksef]:
    endpoint = urlsplit(options.normalized_base_url())
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.username is not None
        or endpoint.query
        or endpoint.fragment
    ):
        raise CliError("A fixed HTTPS API endpoint is required.", ExitCode.CONFIG_ERROR)
    selector = os.environ.get("KSEF_XADES_SELECTOR")
    if selector:
        return _xades_workflow_client(selector, Profile(profile, options.base_url, kind, context))
    scope = login_scope(options.base_url, kind, context)
    with auth_state_lock(profile):
        tokens = get_tokens(profile)
        metadata = recover_refreshed_metadata(get_cached_metadata(profile) or {}, tokens)
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
            retry_after_seconds = parse_retry_after_seconds(exc.retry_after_raw, cap_seconds=None)
            if retry_after_seconds is None and exc.retry_after is not None:
                retry_after_seconds = float(exc.retry_after)
            hint = (
                f"Retry-After: {retry_after_seconds:g} seconds."
                if retry_after_seconds is not None
                else build_rate_limit_hint(exc, default_hint="Wait before the next cycle.")
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
