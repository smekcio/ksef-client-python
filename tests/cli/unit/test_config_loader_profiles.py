from __future__ import annotations

import json

import pytest

from ksef_client.cli.config import loader, paths, profiles
from ksef_client.cli.config.schema import CliConfig, ProfileConfig
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_loader_roundtrip(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    source = CliConfig(
        active_profile="demo",
        profiles={
            "demo": ProfileConfig(
                name="demo",
                env="DEMO",
                base_url="https://api-demo.ksef.mf.gov.pl",
                context_type="nip",
                context_value="123",
            )
        },
    )
    loader.save_config(source)
    loaded = loader.load_config()

    assert loaded.active_profile == "demo"
    assert loaded.profiles["demo"].env == "DEMO"
    assert loaded.profiles["demo"].context_value == "123"


def test_loader_missing_or_invalid_payload_returns_empty(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    assert loader.load_config().profiles == {}

    config_path.write_text("{broken", encoding="utf-8")
    with pytest.warns(RuntimeWarning, match="invalid JSON"):
        assert loader.load_config().profiles == {}
    assert not config_path.exists()
    assert len(list(tmp_path.glob("config.corrupt-*.json"))) == 1
    backup_path = list(tmp_path.glob("config.corrupt-*.json"))[0]

    backup_path.replace(config_path)
    config_path.write_text(json.dumps(["bad"]), encoding="utf-8")
    with pytest.warns(RuntimeWarning, match="invalid root object"):
        assert loader.load_config().profiles == {}

    config_path.write_text(
        json.dumps(
            {
                "active_profile": "demo",
                "profiles": {"demo": {"base_url": "x", "context_type": "nip"}},
            }
        ),
        encoding="utf-8",
    )
    assert loader.load_config().profiles == {}


def test_loader_profile_parser_skips_invalid_entries(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    payload = {
        "active_profile": "demo",
        "profiles": {
            "demo": [],
            "bad_base": {"base_url": 1, "context_type": "nip", "context_value": "x"},
            "bad_context_type": {"base_url": "x", "context_type": 1, "context_value": "x"},
            "bad_context_value": {"base_url": "x", "context_type": "nip", "context_value": 1},
            "bad_env": {"base_url": "x", "context_type": "nip", "context_value": "x", "env": 1},
        },
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    assert loader.load_config().profiles == {}


def test_loader_skips_non_string_profile_names(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)
    monkeypatch.setattr(
        loader.json,
        "loads",
        lambda _: {
            "active_profile": "demo",
            "profiles": {1: {"base_url": "x", "context_type": "nip", "context_value": "y"}},
        },
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("{}", encoding="utf-8")
    assert loader.load_config().profiles == {}


def test_loader_save_error_maps_to_cli_error(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)
    monkeypatch.setattr(
        loader.tempfile,
        "NamedTemporaryFile",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(CliError) as exc:
        loader.save_config(CliConfig())
    assert exc.value.code == ExitCode.CONFIG_ERROR


def test_loader_save_config_uses_atomic_rename(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    loader.save_config(CliConfig())

    assert config_path.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_loader_corrupt_quarantine_warns_when_replace_fails(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)
    config_path.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr(
        config_path.__class__,
        "replace",
        lambda self, target: (_ for _ in ()).throw(OSError("deny")),
        raising=False,
    )

    with pytest.warns(RuntimeWarning, match="could not be quarantined"):
        loaded = loader.load_config()
    assert loaded.profiles == {}


def test_loader_quarantine_noop_when_file_missing(tmp_path) -> None:
    missing_path = tmp_path / "missing.json"
    loader._quarantine_corrupt_config(missing_path, reason="missing")
    assert not list(tmp_path.glob("*.corrupt-*.json"))


def test_loader_load_config_handles_read_oserror(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)
    config_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        config_path.__class__,
        "read_text",
        lambda self, encoding="utf-8": (_ for _ in ()).throw(OSError("denied")),
        raising=False,
    )

    loaded = loader.load_config()
    assert loaded.profiles == {}


def test_loader_save_error_cleans_temp_even_when_unlink_fails(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    class _TmpPath:
        def replace(self, target):
            _ = target
            raise OSError("replace-fail")

        def unlink(self, missing_ok=True):
            _ = missing_ok
            raise OSError("unlink-fail")

    class _TmpCtx:
        def __init__(self):
            self.name = "tmp-name"

        def write(self, data):
            _ = data

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = (exc_type, exc, tb)
            return False

    monkeypatch.setattr(loader.tempfile, "NamedTemporaryFile", lambda **kwargs: _TmpCtx())
    monkeypatch.setattr(loader, "Path", lambda _: _TmpPath())

    with pytest.raises(CliError) as exc:
        loader.save_config(CliConfig())
    assert exc.value.code == ExitCode.CONFIG_ERROR


def test_profiles_helpers_validation_and_updates() -> None:
    config = CliConfig()
    assert profiles.normalize_profile_name("  ") == "demo"
    assert profiles.normalize_profile_name(" team ") == "team"
    default_url, default_env = profiles.resolve_base_url(env=None, base_url=None)
    assert default_env == "DEMO"
    assert default_url.startswith("https://")

    profile = profiles.create_profile(
        config,
        name="demo",
        env="DEMO",
        base_url=None,
        context_type="nip",
        context_value="123",
    )
    assert profile.env == "DEMO"

    with pytest.raises(CliError) as duplicate:
        profiles.create_profile(
            config,
            name="demo",
            env="DEMO",
            base_url=None,
            context_type="nip",
            context_value="123",
        )
    assert duplicate.value.code == ExitCode.VALIDATION_ERROR

    profiles.set_active_profile(config, name="demo")
    updated = profiles.set_profile_value(config, name="demo", key="env", value="TEST")
    assert updated.env == "TEST"
    updated_context_type = profiles.set_profile_value(
        config,
        name="demo",
        key="context_type",
        value="internalid",
    )
    assert updated_context_type.context_type == "internalid"
    updated_context_value = profiles.set_profile_value(
        config,
        name="demo",
        key="context_value",
        value="ABC",
    )
    assert updated_context_value.context_value == "ABC"

    with pytest.raises(CliError) as bad_key:
        profiles.set_profile_value(config, name="demo", key="bad", value="x")
    assert bad_key.value.code == ExitCode.VALIDATION_ERROR

    with pytest.raises(CliError) as bad_value:
        profiles.set_profile_value(config, name="demo", key="base_url", value=" ")
    assert bad_value.value.code == ExitCode.VALIDATION_ERROR

    with pytest.raises(CliError) as bad_env:
        profiles.resolve_base_url(env="bad", base_url=None)
    assert bad_env.value.code == ExitCode.VALIDATION_ERROR

    profiles.delete_profile(config, name="demo")
    assert config.profiles == {}

    with pytest.raises(CliError) as missing:
        profiles.require_profile(config, name="missing")
    assert missing.value.code == ExitCode.CONFIG_ERROR


def test_profiles_upsert_and_active_fallback() -> None:
    config = CliConfig(
        active_profile="one",
        profiles={
            "one": ProfileConfig(
                name="one",
                env="DEMO",
                base_url="https://api-demo.ksef.mf.gov.pl",
                context_type="nip",
                context_value="1",
            ),
            "two": ProfileConfig(
                name="two",
                env="TEST",
                base_url="https://api-test.ksef.mf.gov.pl",
                context_type="nip",
                context_value="2",
            ),
        },
    )
    _, existed = profiles.upsert_profile(
        config,
        name="one",
        env="PROD",
        base_url=None,
        context_type="nip",
        context_value="3",
    )
    assert existed is True
    assert config.profiles["one"].env == "PROD"

    profiles.delete_profile(config, name="one")
    assert config.active_profile == "two"
