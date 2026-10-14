from __future__ import annotations

import os
import time
import warnings
from pathlib import Path

import pytest

from ksef_client.cli.auth import token_cache
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_token_cache_roundtrip(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)

    token_cache.set_cached_metadata("demo", {"method": "token", "x": "y"})
    metadata = token_cache.get_cached_metadata("demo")

    assert metadata is not None
    assert metadata["method"] == "token"
    assert metadata["x"] == "y"
    assert "updated_at" in metadata

    token_cache.clear_cached_metadata("demo")
    assert token_cache.get_cached_metadata("demo") is None


def test_token_cache_handles_invalid_payload_shapes(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)

    with warnings.catch_warnings():
        # Uszkodzony plik jest teraz odstawiany z ostrzeżeniem (patrz test niżej).
        warnings.simplefilter("ignore")
        cache_path.write_text("{bad", encoding="utf-8")
        assert token_cache._load_cache() == {"profiles": {}}

        cache_path.write_text("[]", encoding="utf-8")
        assert token_cache._load_cache() == {"profiles": {}}

        cache_path.write_text('{"profiles": []}', encoding="utf-8")
        assert token_cache._load_cache() == {"profiles": {}}


def test_token_cache_quarantines_invalid_json(monkeypatch, tmp_path: Path) -> None:
    """Uszkodzony cache jest odstawiany z ostrzeżeniem, nie po cichu ignorowany.

    Bez tego `auth status` pokazywał puste `auth_method`, a `auth revoke-self-token`
    tracił punkt zaczepienia (brak `method` i numeru referencyjnego).
    """
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    cache_path.write_text("{bad", encoding="utf-8")

    with pytest.warns(RuntimeWarning, match="cache is invalid"):
        assert token_cache._load_cache() == {"profiles": {}}

    backups = list(tmp_path.glob("cache.corrupt-*.json"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "{bad"
    assert not cache_path.exists()


def test_token_cache_quarantine_failure_is_tolerated(monkeypatch, tmp_path: Path) -> None:
    """Gdy nie da się odstawić pliku, cache nadal zwraca pusty stan (bez wyjątku)."""
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    cache_path.write_text("{bad", encoding="utf-8")
    monkeypatch.setattr(
        token_cache.os, "replace", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("busy"))
    )

    assert token_cache._load_cache() == {"profiles": {}}


def test_token_cache_read_failure_returns_empty(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    cache_path.write_text('{"profiles":{}}', encoding="utf-8")
    original_read_text = Path.read_text

    def _raise(self: Path, *args, **kwargs):
        if self == cache_path:
            raise OSError("locked")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _raise)

    assert token_cache._load_cache() == {"profiles": {}}


def test_token_cache_lock_timeout_is_reported(monkeypatch, tmp_path: Path) -> None:
    """Zajęta blokada nie może wisieć wiecznie — kończy się czytelnym błędem."""
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    monkeypatch.setattr(token_cache, "_CACHE_LOCK_TIMEOUT_SECONDS", 0.0)
    lock_path = cache_path.with_name("cache.json.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("", encoding="utf-8")

    with pytest.raises(CliError, match="Timed out waiting"):
        token_cache.set_cached_metadata("demo", {"method": "token"})


def test_token_cache_lock_waits_for_release(monkeypatch, tmp_path: Path) -> None:
    """Blokada zajęta przez inny proces jest odczekiwana, a nie ignorowana."""
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    lock_path = cache_path.with_name("cache.json.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("", encoding="utf-8")
    waits: list[float] = []

    def _sleep(seconds: float) -> None:
        waits.append(seconds)
        # Inny proces zwalnia blokadę po chwili.
        lock_path.unlink()

    monkeypatch.setattr(token_cache.time, "sleep", _sleep)

    token_cache.set_cached_metadata("demo", {"method": "token"})

    assert waits == [token_cache._CACHE_LOCK_POLL_INTERVAL_SECONDS]
    assert token_cache.get_cached_metadata("demo") is not None


def test_token_cache_steals_an_orphaned_lock(monkeypatch, tmp_path: Path) -> None:
    """Blokada po zabitym procesie nie może blokować cache na zawsze.

    Proces zabity w trakcie nie sprząta pliku blokady — wcześniej każde kolejne
    wywołanie kończyło się `CliError` po 5 s, dopóki człowiek nie usunął pliku
    ręcznie.
    """
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    lock_path = cache_path.with_name("cache.json.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("999999 1.0", encoding="utf-8")
    stale_time = time.time() - token_cache._CACHE_LOCK_STALE_SECONDS - 5
    os.utime(lock_path, (stale_time, stale_time))

    token_cache.set_cached_metadata("demo", {"method": "token"})

    metadata = token_cache.get_cached_metadata("demo")
    assert metadata is not None
    assert metadata["method"] == "token"
    assert not lock_path.exists()


def test_token_cache_lock_steal_attempts_are_bounded(monkeypatch, tmp_path: Path) -> None:
    """Gdy starej blokady nie da się usunąć, pętla kończy się błędem, a nie kręci.

    Wcześniej gałąź „stale” robiła `continue` bez sprawdzania timeoutu i bez
    `sleep`, więc przy `unlink` blokowanym przez system (np. brak praw) proces
    kręcił się w miejscu w nieskończoność.
    """
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    lock_path = cache_path.with_name("cache.json.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("999999 1.0", encoding="utf-8")
    stale_time = time.time() - token_cache._CACHE_LOCK_STALE_SECONDS - 5
    os.utime(lock_path, (stale_time, stale_time))
    monkeypatch.setattr(token_cache, "_CACHE_LOCK_TIMEOUT_SECONDS", 0.0)
    attempts: list[int] = []

    def _busy(self: Path, **kwargs: object) -> None:
        _ = (self, kwargs)
        attempts.append(1)
        if len(attempts) > token_cache._CACHE_LOCK_MAX_STEALS:
            # Stara implementacja kręciła się tu w miejscu — zamieniamy zawieszenie
            # na szybki błąd, żeby regresja była widoczna od razu.
            raise AssertionError("pętla przejmowania blokady nie jest ograniczona")
        raise OSError("busy")

    monkeypatch.setattr(Path, "unlink", _busy)

    with pytest.raises(CliError, match="Timed out waiting"):
        token_cache.get_cached_metadata("demo")

    assert len(attempts) <= token_cache._CACHE_LOCK_MAX_STEALS


def test_token_cache_lock_is_not_stale_when_stat_fails(monkeypatch, tmp_path: Path) -> None:
    """Gdy nie da się odczytać wieku blokady, nie przejmujemy jej na ślepo."""
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    lock_path = cache_path.with_name("cache.json.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("1 1.0", encoding="utf-8")
    original_stat = Path.stat

    def _stat(self: Path, *, follow_symlinks: bool = True):
        if self == lock_path:
            raise OSError("locked")
        return original_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)

    assert token_cache._lock_is_stale(lock_path) is False


def test_token_cache_lock_creation_error_is_wrapped(monkeypatch, tmp_path: Path) -> None:
    """Błąd utworzenia blokady (np. brak praw) to `CliError`, nie surowy OSError."""
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)

    def _denied(*args: object, **kwargs: object) -> int:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(token_cache.os, "open", _denied)

    with pytest.raises(CliError, match="Cannot create the token metadata cache lock"):
        token_cache.get_cached_metadata("demo")


def test_token_cache_lock_directory_error_is_wrapped(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)

    def _denied(*args: object, **kwargs: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "mkdir", _denied)

    with pytest.raises(CliError, match="Cannot create the token metadata cache directory"):
        token_cache.set_cached_metadata("demo", {"method": "token"})


def test_token_cache_chmod_is_applied_on_posix(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    monkeypatch.setattr(token_cache.os, "name", "posix", raising=False)
    calls: list[tuple[Path, int]] = []
    monkeypatch.setattr(
        token_cache.os, "chmod", lambda path, mode: calls.append((Path(path), mode))
    )

    token_cache.set_cached_metadata("demo", {"method": "token"})

    assert calls and calls[0][1] == 0o600


def test_token_cache_chmod_failure_is_tolerated(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    monkeypatch.setattr(token_cache.os, "name", "posix", raising=False)
    monkeypatch.setattr(
        token_cache.os, "chmod", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied"))
    )

    token_cache.set_cached_metadata("demo", {"method": "token"})

    assert token_cache.get_cached_metadata("demo") is not None


def test_token_cache_set_write_failure_is_wrapped_in_cli_error(
    monkeypatch, tmp_path: Path
) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)

    original_write_text = Path.write_text

    def _raise_on_write(self: Path, *args, **kwargs):
        # Zapis jest atomowy (tmp + `os.replace`), więc błąd dotyczy pliku
        # tymczasowego w tym samym katalogu, nie samego `cache.json`.
        if self.parent == cache_path.parent:
            raise OSError("disk full")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _raise_on_write)

    with pytest.raises(CliError) as exc:
        token_cache.set_cached_metadata("demo", {"method": "token"})
    assert exc.value.code == ExitCode.CONFIG_ERROR
    assert exc.value.hint is not None
    assert "write access" in exc.value.hint.lower()


def test_token_cache_clear_write_failure_is_wrapped_in_cli_error(
    monkeypatch, tmp_path: Path
) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)
    cache_path.write_text('{"profiles":{"demo":{"method":"token"}}}', encoding="utf-8")

    original_write_text = Path.write_text

    def _raise_on_write(self: Path, *args, **kwargs):
        if self.parent == cache_path.parent:
            raise OSError("disk full")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _raise_on_write)

    with pytest.raises(CliError) as exc:
        token_cache.clear_cached_metadata("demo")
    assert exc.value.code == ExitCode.CONFIG_ERROR
    assert exc.value.hint is not None
    assert "cache" in exc.value.message.lower()
