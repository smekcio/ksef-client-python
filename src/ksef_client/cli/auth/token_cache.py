from __future__ import annotations

import json
import os
import time
import warnings
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path

from ..config.paths import cache_file
from ..errors import CliError
from ..exit_codes import ExitCode

#: Czas oczekiwania na blokadę pliku cache (sekundy) i interwał odpytywania.
_CACHE_LOCK_TIMEOUT_SECONDS = 5.0
_CACHE_LOCK_POLL_INTERVAL_SECONDS = 0.05
#: Blokada starsza niż tyle sekund jest uznawana za osieroconą (proces, który ją
#: trzymał, został zabity) i jest przejmowana. Sekcja krytyczna to odczyt i zapis
#: małego JSON-a, więc próg jest z zapasem większy od realnego czasu trzymania.
_CACHE_LOCK_STALE_SECONDS = 30.0


def _cache_lock_file() -> Path:
    path = cache_file()
    return path.with_name(f"{path.name}.lock")


def _lock_is_stale(lock_path: Path) -> bool:
    """Czy plik blokady pochodzi po procesie, który padł bez sprzątania."""
    try:
        age = time.time() - lock_path.stat().st_mtime
    except OSError:
        return False
    return age >= _CACHE_LOCK_STALE_SECONDS


@contextmanager
def _cache_lock() -> Iterator[None]:
    """Blokada międzyprocesowa wokół odczytu i zapisu cache.

    Bez niej dwa równoległe uruchomienia CLI (każde pisze metadane swojego
    profilu) nadpisywały się nawzajem i gubiły wpisy — potwierdzone uruchomieniem
    czterech procesów, z których na dysku została jedna zmiana.

    Blokada to plik z PID-em właściciela. Proces zabity w trakcie nie posprząta
    jej, dlatego blokada starsza niż `_CACHE_LOCK_STALE_SECONDS` jest
    przejmowana — inaczej jedno `Stop-Process -Force` trwale odbierało
    możliwość odczytu metadanych tokenów.
    """
    lock_path = _cache_lock_file()
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CliError(
            "Cannot create the token metadata cache directory.",
            ExitCode.CONFIG_ERROR,
            "Grant write access to cache directory or update cache location settings.",
        ) from exc

    started = time.monotonic()
    handle: int | None = None
    while handle is None:
        try:
            handle = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError as exc:
            if _lock_is_stale(lock_path):
                # Poprzedni właściciel padł bez sprzątania — przejmujemy blokadę.
                with suppress(OSError):
                    lock_path.unlink()
                continue
            if time.monotonic() - started >= _CACHE_LOCK_TIMEOUT_SECONDS:
                raise CliError(
                    "Timed out waiting for the token metadata cache lock.",
                    ExitCode.CONFIG_ERROR,
                    "Another ksef process may be running; retry in a moment.",
                ) from exc
            time.sleep(_CACHE_LOCK_POLL_INTERVAL_SECONDS)
        except OSError as exc:
            raise CliError(
                "Cannot create the token metadata cache lock.",
                ExitCode.CONFIG_ERROR,
                "Grant write access to cache directory or update cache location settings.",
            ) from exc
    try:
        with suppress(OSError):
            os.write(handle, f"{os.getpid()} {time.time():.3f}".encode("ascii"))
        yield
    finally:
        with suppress(OSError):
            os.close(handle)
        with suppress(OSError):
            lock_path.unlink()


def _corrupt_backup_name(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return path.with_name(f"{path.stem}.corrupt-{timestamp}{path.suffix}")


def _quarantine_corrupt_cache(path: Path, *, reason: str) -> None:
    """Odstawia uszkodzony cache i ostrzega — zamiast po cichu go ignorować.

    `config.json` jest traktowany w ten sposób od dawna, a `cache.json` nie:
    uszkodzony plik wyglądał jak brak metadanych, więc `auth status` pokazywał
    puste `auth_method`, a `auth revoke-self-token` tracił punkt zaczepienia.
    """
    backup = _corrupt_backup_name(path)
    try:
        os.replace(path, backup)
    except OSError:
        return
    warnings.warn(
        f"Token metadata cache is invalid ({reason}). Original file moved to {backup}.",
        RuntimeWarning,
        stacklevel=3,
    )


def _load_cache() -> dict[str, dict[str, dict[str, str]]]:
    path = cache_file()
    if not path.exists():
        return {"profiles": {}}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {"profiles": {}}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        _quarantine_corrupt_cache(path, reason="invalid JSON")
        return {"profiles": {}}
    if not isinstance(payload, dict) or not isinstance(payload.get("profiles"), dict):
        _quarantine_corrupt_cache(path, reason="unexpected shape")
        return {"profiles": {}}
    return {"profiles": payload["profiles"]}


def _save_cache(payload: dict[str, dict[str, dict[str, str]]]) -> None:
    path = cache_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Zapis atomowy: `write_text` w miejscu zostawiał częściowo zapisany plik
        # przy przerwanym procesie, a brak `os.replace` pozwalał czytelnikowi
        # zobaczyć połowę dokumentu.
        temp_path = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8"
        )
        os.replace(temp_path, path)
    except OSError as exc:
        with suppress(OSError, UnboundLocalError):
            temp_path.unlink()
        raise CliError(
            "Cannot persist token metadata cache.",
            ExitCode.CONFIG_ERROR,
            "Grant write access to cache directory or update cache location settings.",
        ) from exc
    if os.name != "nt":
        with suppress(OSError):
            os.chmod(path, 0o600)


def get_cached_metadata(profile: str) -> dict[str, str] | None:
    with _cache_lock():
        payload = _load_cache()
    profile_data = payload["profiles"].get(profile)
    if not isinstance(profile_data, dict):
        return None
    return {str(k): str(v) for k, v in profile_data.items()}


def set_cached_metadata(profile: str, metadata: dict[str, str]) -> None:
    with _cache_lock():
        payload = _load_cache()
        data = dict(metadata)
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        payload["profiles"][profile] = data
        _save_cache(payload)


def clear_cached_metadata(profile: str) -> None:
    with _cache_lock():
        payload = _load_cache()
        if profile in payload["profiles"]:
            del payload["profiles"][profile]
            _save_cache(payload)
