from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import time
import uuid
import warnings
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, NoReturn, Protocol, cast

from ..config.paths import cache_dir
from ..errors import CliError
from ..exit_codes import ExitCode

try:
    _fernet_module = importlib.import_module("cryptography.fernet")
    _FernetClass = cast(Any, _fernet_module.Fernet)
    InvalidTokenType = cast(type[Exception], _fernet_module.InvalidToken)
except Exception:  # pragma: no cover - optional dependency path
    _FernetClass = None

    class _InvalidToken(Exception):
        pass

    InvalidTokenType = _InvalidToken

_keyring: Any = None
try:
    _keyring = importlib.import_module("keyring")
    _keyring_errors = importlib.import_module("keyring.errors")
    KeyringErrorType = cast(type[Exception], _keyring_errors.KeyringError)

    _KEYRING_AVAILABLE = True
except Exception:  # pragma: no cover - import fallback path
    class _KeyringError(Exception):
        pass

    KeyringErrorType = _KeyringError
    _KEYRING_AVAILABLE = False

KeyringError = KeyringErrorType

_SERVICE_NAME = "ksef-client-python-cli"
_ACCESS_KEY = "access_token"
_REFRESH_KEY = "refresh_token"
_FALLBACK_FILE_NAME = "tokens.json"
_FALLBACK_LOCK_SUFFIX = ".lock"
_FALLBACK_LOCK_TIMEOUT_SECONDS = 2.0
_FALLBACK_LOCK_POLL_INTERVAL_SECONDS = 0.05
_ALLOW_INSECURE_FALLBACK_ENV = "KSEF_CLI_ALLOW_INSECURE_TOKEN_STORE"
_TOKEN_STORE_KEY_ENV = "KSEF_CLI_TOKEN_STORE_KEY"
_ENCRYPTION_MODE = "fernet-v1"
_PLAINTEXT_FALLBACK_WARNING = (
    "Using plaintext token fallback storage. Tokens are stored unencrypted in tokens.json."
)
_PLAINTEXT_WARNING_EMITTED = False


class _KeyringBackend(Protocol):
    def set_password(self, service: str, key: str, value: str) -> None: ...

    def get_password(self, service: str, key: str) -> str | None: ...

    def delete_password(self, service: str, key: str) -> None: ...


def _token_key(profile: str, key: str) -> str:
    return f"{profile}:{key}"


def _fallback_tokens_file() -> Path:
    return cache_dir() / _FALLBACK_FILE_NAME


def _fallback_tokens_lock_file() -> Path:
    path = _fallback_tokens_file()
    return path.with_name(f"{path.name}{_FALLBACK_LOCK_SUFFIX}")


def _allow_insecure_fallback() -> bool:
    value = os.getenv(_ALLOW_INSECURE_FALLBACK_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _plaintext_fallback_allowed() -> bool:
    # On Windows we do not allow plaintext token fallback due to weaker default file ACLs.
    return _allow_insecure_fallback() and os.name != "nt"


def _token_store_key() -> str | None:
    value = os.getenv(_TOKEN_STORE_KEY_ENV, "").strip()
    if not value:
        return None
    return value


def _encrypted_fallback_enabled() -> bool:
    return _token_store_key() is not None and _FernetClass is not None


def _fallback_mode() -> str | None:
    if _encrypted_fallback_enabled():
        return _ENCRYPTION_MODE
    if _plaintext_fallback_allowed():
        return "insecure-plaintext"
    return None


def get_token_store_mode() -> str:
    if _KEYRING_AVAILABLE and _keyring is not None:
        return "keyring"
    if _encrypted_fallback_enabled():
        return "encrypted-fallback"
    if _plaintext_fallback_allowed():
        return "plaintext-fallback"
    return "unavailable"


def _warn_plaintext_fallback_used(mode: str | None) -> None:
    global _PLAINTEXT_WARNING_EMITTED
    if mode != "insecure-plaintext" or _PLAINTEXT_WARNING_EMITTED:
        return
    warnings.warn(_PLAINTEXT_FALLBACK_WARNING, UserWarning, stacklevel=3)
    _PLAINTEXT_WARNING_EMITTED = True


def _fallback_cipher() -> Any:
    key = _token_store_key()
    if key is None or _FernetClass is None:
        raise CliError(
            "Encrypted fallback token store is unavailable.",
            ExitCode.CONFIG_ERROR,
            f"Set {_TOKEN_STORE_KEY_ENV} and ensure cryptography is installed.",
        )
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    fernet_key = base64.urlsafe_b64encode(digest)
    return _FernetClass(fernet_key)


def _raise_no_secure_store() -> NoReturn:
    fallback_hint = (
        f"(or {_ALLOW_INSECURE_FALLBACK_ENV}=1 for plaintext fallback)."
        if os.name != "nt"
        else "(plaintext fallback is disabled on Windows)."
    )
    raise CliError(
        "Secure token storage backend is not available.",
        ExitCode.CONFIG_ERROR,
        "Install/configure OS keyring backend or set "
        f"{_TOKEN_STORE_KEY_ENV} for encrypted fallback {fallback_hint}",
    )


def _load_fallback_tokens() -> dict[str, dict[str, Any]]:
    path = _fallback_tokens_file()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(payload, dict):
        return {}

    result: dict[str, dict[str, Any]] = {}
    for profile, value in payload.items():
        if not isinstance(profile, str) or not isinstance(value, dict):
            continue
        result[profile] = value
    return result


def _save_fallback_tokens(payload: dict[str, dict[str, Any]]) -> None:
    path = _fallback_tokens_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, ensure_ascii=True, indent=2)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            with suppress(OSError):
                os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except OSError:
        with suppress(OSError):
            temp_path.unlink()
        raise
    if os.name != "nt":
        with suppress(OSError):
            os.chmod(path, 0o600)


@contextmanager
def _fallback_tokens_lock() -> Iterator[None]:
    lock_path = _fallback_tokens_lock_file()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle: int | None = None
    started = time.monotonic()
    while handle is None:
        try:
            handle = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError as exc:
            if time.monotonic() - started >= _FALLBACK_LOCK_TIMEOUT_SECONDS:
                raise OSError("Timed out waiting for fallback token store lock.") from exc
            time.sleep(_FALLBACK_LOCK_POLL_INTERVAL_SECONDS)
    try:
        yield
    finally:
        with suppress(OSError):
            os.close(handle)
        with suppress(OSError):
            lock_path.unlink()


def _update_fallback_tokens(profile: str, data: dict[str, Any] | None) -> None:
    with _fallback_tokens_lock():
        payload = _load_fallback_tokens()
        if data is None:
            if profile not in payload:
                return
            del payload[profile]
        else:
            payload[profile] = data
        _save_fallback_tokens(payload)


def _encode_tokens(*, access_token: str, refresh_token: str, mode: str) -> dict[str, str]:
    if mode == _ENCRYPTION_MODE:
        cipher = _fallback_cipher()
        return {
            "enc": _ENCRYPTION_MODE,
            _ACCESS_KEY: cipher.encrypt(access_token.encode("utf-8")).decode("utf-8"),
            _REFRESH_KEY: cipher.encrypt(refresh_token.encode("utf-8")).decode("utf-8"),
        }
    return {
        _ACCESS_KEY: access_token,
        _REFRESH_KEY: refresh_token,
    }


def _decode_tokens(data: dict[str, Any]) -> tuple[str, str] | None:
    mode = data.get("enc")
    access = data.get(_ACCESS_KEY)
    refresh = data.get(_REFRESH_KEY)
    if not isinstance(access, str) or not isinstance(refresh, str):
        return None

    if mode == _ENCRYPTION_MODE:
        try:
            cipher = _fallback_cipher()
            access_plain = cipher.decrypt(access.encode("utf-8")).decode("utf-8")
            refresh_plain = cipher.decrypt(refresh.encode("utf-8")).decode("utf-8")
        except (CliError, InvalidTokenType, UnicodeDecodeError):
            return None
        return access_plain, refresh_plain

    if _plaintext_fallback_allowed():
        return access, refresh
    return None


def save_tokens(profile: str, access_token: str, refresh_token: str) -> None:
    keyring_backend = cast(_KeyringBackend | None, _keyring)
    if _KEYRING_AVAILABLE and keyring_backend is not None:
        try:
            keyring_backend.set_password(
                _SERVICE_NAME, _token_key(profile, _ACCESS_KEY), access_token
            )
            keyring_backend.set_password(
                _SERVICE_NAME, _token_key(profile, _REFRESH_KEY), refresh_token
            )
            return
        except KeyringError as exc:
            if _fallback_mode() is None:
                fallback_hint = (
                    f"(or {_ALLOW_INSECURE_FALLBACK_ENV}=1 for plaintext fallback)."
                    if os.name != "nt"
                    else "(plaintext fallback is disabled on Windows)."
                )
                raise CliError(
                    "Cannot save tokens in system keyring.",
                    ExitCode.CONFIG_ERROR,
                    "Configure OS keyring backend or set "
                    f"{_TOKEN_STORE_KEY_ENV} for encrypted fallback "
                    f"{fallback_hint}",
                ) from exc

    mode = _fallback_mode()
    if mode is None:
        _raise_no_secure_store()
    _warn_plaintext_fallback_used(mode)
    encoded_tokens = _encode_tokens(
        access_token=access_token, refresh_token=refresh_token, mode=mode
    )
    try:
        _update_fallback_tokens(profile, encoded_tokens)
    except OSError as exc:
        raise CliError(
            "Cannot persist tokens in fallback file store.",
            ExitCode.CONFIG_ERROR,
            "Grant write access to cache directory or configure OS keyring backend.",
        ) from exc


def clear_tokens(profile: str) -> None:
    keyring_backend = cast(_KeyringBackend | None, _keyring)
    if _KEYRING_AVAILABLE and keyring_backend is not None:
        for key in (_ACCESS_KEY, _REFRESH_KEY):
            try:
                keyring_backend.delete_password(_SERVICE_NAME, _token_key(profile, key))
            except KeyringError:
                # Missing entry/backend issues are non-fatal for logout path.
                continue

    if not _fallback_tokens_file().exists():
        return

    with suppress(OSError):
        _update_fallback_tokens(profile, None)


def get_tokens(profile: str) -> tuple[str, str] | None:
    keyring_backend = cast(_KeyringBackend | None, _keyring)
    if _KEYRING_AVAILABLE and keyring_backend is not None:
        try:
            access = keyring_backend.get_password(_SERVICE_NAME, _token_key(profile, _ACCESS_KEY))
            refresh = keyring_backend.get_password(_SERVICE_NAME, _token_key(profile, _REFRESH_KEY))
        except KeyringError:
            access = None
            refresh = None
        if access and refresh:
            return access, refresh
        if _fallback_mode() is None:
            return None

    mode = _fallback_mode()
    if mode is not None:
        _warn_plaintext_fallback_used(mode)
        payload = _load_fallback_tokens()
        profile_data = payload.get(profile)
        if not isinstance(profile_data, dict):
            return None
        decoded = _decode_tokens(profile_data)
        if decoded is None:
            return None
        access, refresh = decoded
    else:
        return None
    if not access or not refresh:
        return None
    return access, refresh
