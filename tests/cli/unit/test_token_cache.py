from __future__ import annotations

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

    cache_path.write_text("{bad", encoding="utf-8")
    assert token_cache._load_cache() == {"profiles": {}}

    cache_path.write_text("[]", encoding="utf-8")
    assert token_cache._load_cache() == {"profiles": {}}

    cache_path.write_text('{"profiles": []}', encoding="utf-8")
    assert token_cache._load_cache() == {"profiles": {}}


def test_token_cache_set_write_failure_is_wrapped_in_cli_error(
    monkeypatch, tmp_path: Path
) -> None:
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(token_cache, "cache_file", lambda: cache_path)

    original_write_text = Path.write_text

    def _raise_on_write(self: Path, *args, **kwargs):
        if self == cache_path:
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
        if self == cache_path:
            raise OSError("disk full")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _raise_on_write)

    with pytest.raises(CliError) as exc:
        token_cache.clear_cached_metadata("demo")
    assert exc.value.code == ExitCode.CONFIG_ERROR
    assert exc.value.hint is not None
    assert "cache" in exc.value.message.lower()
