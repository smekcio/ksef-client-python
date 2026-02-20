from __future__ import annotations

from pathlib import Path
from typing import Any

from ksef_client.config import KsefEnvironment
from ksef_client.services.workflows import AuthCoordinator
from ksef_client.services.xades import XadesKeyPair

from ..config.loader import load_config
from ..errors import CliError
from ..exit_codes import ExitCode
from ..sdk.factory import create_client
from .keyring_store import clear_tokens, get_tokens, save_tokens
from .token_cache import clear_cached_metadata, get_cached_metadata, set_cached_metadata


def _select_certificate(certs: list[dict[str, Any]], usage_name: str) -> str:
    for cert in certs:
        usage = cert.get("usage") or []
        if usage_name in usage and cert.get("certificate"):
            return str(cert["certificate"])
    raise CliError(
        f"Missing KSeF public certificate usage: {usage_name}.",
        ExitCode.API_ERROR,
        "Try again later or verify environment availability.",
    )


def _require_non_empty(value: str | None, message: str, hint: str) -> str:
    if value is None or value.strip() == "":
        raise CliError(message, ExitCode.VALIDATION_ERROR, hint)
    return value.strip()


def _profile_context(profile: str) -> tuple[str | None, str | None, str | None]:
    config = load_config()
    profile_cfg = config.profiles.get(profile)
    if profile_cfg is None:
        return None, None, None
    return profile_cfg.base_url, profile_cfg.context_type, profile_cfg.context_value


def resolve_base_url(base_url: str | None, *, profile: str | None = None) -> str:
    if base_url and base_url.strip():
        return base_url.strip()
    if profile:
        profile_base_url, _, _ = _profile_context(profile)
        if profile_base_url and profile_base_url.strip():
            return profile_base_url.strip()
    return KsefEnvironment.DEMO.value


def login_with_token(
    *,
    profile: str,
    base_url: str,
    token: str | None,
    context_type: str | None,
    context_value: str | None,
    poll_interval: float,
    max_attempts: int,
    save: bool = True,
) -> dict[str, Any]:
    _, profile_context_type, profile_context_value = _profile_context(profile)
    safe_token = _require_non_empty(
        token,
        "KSeF token is required.",
        "Use --ksef-token or set KSEF_TOKEN environment variable.",
    )
    safe_context_type = _require_non_empty(
        context_type or profile_context_type,
        "Context type is required.",
        "Use --context-type, set KSEF_CONTEXT_TYPE or configure profile context_type.",
    )
    safe_context_value = _require_non_empty(
        context_value or profile_context_value,
        "Context value is required.",
        "Use --context-value, set KSEF_CONTEXT_VALUE or configure profile context_value.",
    )

    with create_client(base_url) as client:
        certs = client.security.get_public_key_certificates()
        token_cert_pem = _select_certificate(certs, "KsefTokenEncryption")
        result = AuthCoordinator(client.auth).authenticate_with_ksef_token(
            token=safe_token,
            public_certificate=token_cert_pem,
            context_identifier_type=safe_context_type,
            context_identifier_value=safe_context_value,
            poll_interval_seconds=poll_interval,
            max_attempts=max_attempts,
        )

    if save:
        save_tokens(
            profile,
            result.tokens.access_token.token,
            result.tokens.refresh_token.token,
        )
        set_cached_metadata(
            profile,
            {
                "method": "token",
                "access_valid_until": result.tokens.access_token.valid_until or "",
                "refresh_valid_until": result.tokens.refresh_token.valid_until or "",
                "auth_reference_number": result.reference_number,
            },
        )

    return {
        "reference_number": result.reference_number,
        "access_valid_until": result.tokens.access_token.valid_until or "",
        "refresh_valid_until": result.tokens.refresh_token.valid_until or "",
        "saved": save,
    }


def login_with_xades(
    *,
    profile: str,
    base_url: str,
    context_type: str | None,
    context_value: str | None,
    pkcs12_path: str | None,
    pkcs12_password: str | None,
    cert_pem: str | None,
    key_pem: str | None,
    key_password: str | None,
    subject_identifier_type: str,
    poll_interval: float,
    max_attempts: int,
    save: bool = True,
) -> dict[str, Any]:
    _, profile_context_type, profile_context_value = _profile_context(profile)
    safe_context_type = _require_non_empty(
        context_type or profile_context_type,
        "Context type is required.",
        "Use --context-type, set KSEF_CONTEXT_TYPE or configure profile context_type.",
    )
    safe_context_value = _require_non_empty(
        context_value or profile_context_value,
        "Context value is required.",
        "Use --context-value, set KSEF_CONTEXT_VALUE or configure profile context_value.",
    )
    safe_subject_identifier_type = _require_non_empty(
        subject_identifier_type,
        "Subject identifier type is required.",
        "Use --subject-identifier-type.",
    )
    if safe_subject_identifier_type not in {"certificateSubject", "certificateFingerprint"}:
        raise CliError(
            f"Unsupported subject identifier type: {safe_subject_identifier_type}.",
            ExitCode.VALIDATION_ERROR,
            "Use certificateSubject or certificateFingerprint.",
        )

    use_pkcs12 = bool(pkcs12_path and pkcs12_path.strip())
    use_pem_pair = bool((cert_pem and cert_pem.strip()) or (key_pem and key_pem.strip()))
    if use_pkcs12 and use_pem_pair:
        raise CliError(
            "Choose only one XAdES credential source.",
            ExitCode.VALIDATION_ERROR,
            "Use either --pkcs12-path or --cert-pem with --key-pem.",
        )
    if not use_pkcs12 and not use_pem_pair:
        raise CliError(
            "XAdES credentials are required.",
            ExitCode.VALIDATION_ERROR,
            "Use --pkcs12-path or --cert-pem with --key-pem.",
        )

    try:
        if use_pkcs12:
            safe_pkcs12_path = _require_non_empty(
                pkcs12_path,
                "PKCS12 path is required.",
                "Use --pkcs12-path.",
            )
            key_pair = XadesKeyPair.from_pkcs12_file(
                pkcs12_path=safe_pkcs12_path,
                pkcs12_password=pkcs12_password,
            )
        else:
            safe_cert_pem = _require_non_empty(
                cert_pem, "Certificate path is required.", "Use --cert-pem."
            )
            safe_key_pem = _require_non_empty(
                key_pem, "Private key path is required.", "Use --key-pem."
            )
            if not Path(safe_cert_pem).exists():
                raise CliError(
                    f"Certificate file does not exist: {safe_cert_pem}.",
                    ExitCode.VALIDATION_ERROR,
                    "Provide valid --cert-pem path.",
                )
            if not Path(safe_key_pem).exists():
                raise CliError(
                    f"Private key file does not exist: {safe_key_pem}.",
                    ExitCode.VALIDATION_ERROR,
                    "Provide valid --key-pem path.",
                )
            key_pair = XadesKeyPair.from_pem_files(
                certificate_path=safe_cert_pem,
                private_key_path=safe_key_pem,
                private_key_password=key_password,
            )
    except CliError:
        raise
    except (OSError, ValueError) as exc:
        raise CliError(
            "Unable to load XAdES credentials.",
            ExitCode.VALIDATION_ERROR,
            str(exc),
        ) from exc

    with create_client(base_url) as client:
        result = AuthCoordinator(client.auth).authenticate_with_xades_key_pair(
            key_pair=key_pair,
            context_identifier_type=safe_context_type,
            context_identifier_value=safe_context_value,
            subject_identifier_type=safe_subject_identifier_type,
            poll_interval_seconds=poll_interval,
            max_attempts=max_attempts,
        )

    if save:
        save_tokens(
            profile,
            result.tokens.access_token.token,
            result.tokens.refresh_token.token,
        )
        set_cached_metadata(
            profile,
            {
                "method": "xades",
                "access_valid_until": result.tokens.access_token.valid_until or "",
                "refresh_valid_until": result.tokens.refresh_token.valid_until or "",
                "auth_reference_number": result.reference_number,
            },
        )

    return {
        "reference_number": result.reference_number,
        "access_valid_until": result.tokens.access_token.valid_until or "",
        "refresh_valid_until": result.tokens.refresh_token.valid_until or "",
        "saved": save,
    }


def get_auth_status(profile: str) -> dict[str, Any]:
    tokens = get_tokens(profile)
    metadata = get_cached_metadata(profile) or {}
    return {
        "profile": profile,
        "has_tokens": bool(tokens),
        "auth_method": metadata.get("method", ""),
        "access_valid_until": metadata.get("access_valid_until", ""),
        "refresh_valid_until": metadata.get("refresh_valid_until", ""),
        "auth_reference_number": metadata.get("auth_reference_number", ""),
        "updated_at": metadata.get("updated_at", ""),
    }


def refresh_access_token(*, profile: str, base_url: str, save: bool = True) -> dict[str, Any]:
    tokens = get_tokens(profile)
    if not tokens:
        raise CliError(
            "No stored tokens for selected profile.",
            ExitCode.AUTH_ERROR,
            "Run `ksef auth login-token` first.",
        )
    _, refresh_token = tokens
    with create_client(base_url) as client:
        refreshed = client.auth.refresh_access_token(refresh_token)

    access_data = refreshed.get("accessToken") or {}
    new_access_token = access_data.get("token")
    if not isinstance(new_access_token, str) or not new_access_token:
        raise CliError(
            "Refresh response does not contain access token.",
            ExitCode.API_ERROR,
            "Try login again with `ksef auth login-token`.",
        )

    access_valid_until = access_data.get("validUntil")
    if save:
        save_tokens(profile, new_access_token, refresh_token)
        metadata = get_cached_metadata(profile) or {}
        metadata.update(
            {
                "access_valid_until": str(access_valid_until or ""),
                "method": metadata.get("method", "token"),
            }
        )
        set_cached_metadata(profile, metadata)

    return {
        "profile": profile,
        "access_valid_until": str(access_valid_until or ""),
        "saved": save,
    }


def logout(profile: str) -> dict[str, Any]:
    clear_tokens(profile)
    clear_cached_metadata(profile)
    return {
        "profile": profile,
        "logged_out": True,
    }
