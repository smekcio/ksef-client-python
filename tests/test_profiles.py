from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from ksef_client import paths
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.profiles import (
    Profile,
    ProfileError,
    ProfileStore,
    normalize_profile_name,
)


def _store(tmp_path: Path) -> ProfileStore:
    return ProfileStore(tmp_path / "config.json")


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


# --- ścieżki wspólne z CLI ------------------------------------------------


def test_sdk_paths_match_cli_paths() -> None:
    from ksef_client.cli.config import paths as cli_paths

    assert paths.APP_DIR_NAME == cli_paths.APP_DIR_NAME
    assert paths.config_dir() == cli_paths.config_dir()
    assert paths.cache_dir() == cli_paths.cache_dir()
    assert paths.config_file() == cli_paths.config_file()
    assert paths.cache_file() == cli_paths.cache_file()


def test_certificates_dir_lives_under_config_dir() -> None:
    assert paths.certificates_dir() == paths.config_dir() / "certificates"


def test_config_dir_uses_appdata_when_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    assert paths.config_dir() == tmp_path / "roaming" / "ksef-cli"


def test_config_dir_falls_back_to_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
    assert paths.config_dir() == tmp_path / "home" / ".config" / "ksef-cli"


def test_cache_dir_uses_localappdata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert paths.cache_dir() == tmp_path / "local" / "ksef-cli"


def test_cache_dir_falls_back_to_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
    assert paths.cache_dir() == tmp_path / "home" / ".cache" / "ksef-cli"


# --- nazwy profili --------------------------------------------------------


@pytest.mark.parametrize("name", ["prod", "demo-2", "a.b_c", "x" * 64])
def test_normalize_profile_name_accepts_safe_names(name: str) -> None:
    assert normalize_profile_name(name) == name


def test_normalize_profile_name_strips_whitespace() -> None:
    assert normalize_profile_name("  demo  ") == "demo"


@pytest.mark.parametrize("name", ["", "   ", "..", "a/b", "a\\b", "x" * 65, "zażółć"])
def test_normalize_profile_name_rejects_unsafe_names(name: str) -> None:
    with pytest.raises(ProfileError):
        normalize_profile_name(name)


def test_normalize_profile_name_rejects_non_string() -> None:
    with pytest.raises(ProfileError, match="musi być tekstem"):
        normalize_profile_name(1)  # type: ignore[arg-type]


# --- model profilu --------------------------------------------------------


def test_profile_environment_recognises_known_base_urls() -> None:
    assert Profile("t", KsefEnvironment.TEST.value, "nip", "1").environment is KsefEnvironment.TEST
    assert (
        Profile("d", KsefEnvironment.DEMO.value + "/", "nip", "1").environment
        is KsefEnvironment.DEMO
    )
    assert (
        Profile("p", KsefEnvironment.PROD.value, "nip", "1").environment is KsefEnvironment.PROD
    )


def test_profile_environment_returns_none_for_custom_url() -> None:
    assert Profile("c", "https://proxy.example.com/api", "nip", "1").environment is None


def test_profile_to_options_maps_base_url_and_overrides() -> None:
    profile = Profile("demo", KsefEnvironment.DEMO.value, "nip", "123")

    options = profile.to_options(timeout_seconds=5.0)

    assert options.base_url == KsefEnvironment.DEMO.value
    assert options.timeout_seconds == 5.0


def test_profile_to_options_allows_base_url_override() -> None:
    profile = Profile("demo", KsefEnvironment.DEMO.value, "nip", "123")

    options = profile.to_options(base_url="https://example.com")

    assert options.base_url == "https://example.com"


# --- magazyn: odczyt ------------------------------------------------------


def test_default_store_uses_standard_config_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    assert ProfileStore.default().path == paths.config_file()


def test_missing_file_is_empty_store(tmp_path: Path) -> None:
    store = _store(tmp_path)

    assert store.list() == ()
    assert store.active_name() is None
    assert store.active() is None
    assert store.find("demo") is None


def test_list_sorts_and_skips_invalid_entries(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(
        store.path,
        {
            "version": 1,
            "active_profile": "b",
            "profiles": {
                "b": {
                    "base_url": KsefEnvironment.TEST.value,
                    "context_type": "nip",
                    "context_value": "2",
                    "env": "TEST",
                },
                "a": {
                    "base_url": KsefEnvironment.DEMO.value,
                    "context_type": "nip",
                    "context_value": "1",
                    "env": "DEMO",
                },
                "broken": {"base_url": 5},
                "broken2": "not-a-dict",
                3: {"base_url": "x"},
            },
        },
    )

    assert [profile.name for profile in store.list()] == ["a", "b"]
    assert store.active_name() == "b"


@pytest.mark.parametrize(
    "payload",
    [
        {"base_url": "x", "context_type": "nip", "context_value": 5},
        {"base_url": "x", "context_type": "nip", "context_value": "1", "env": 5},
    ],
)
def test_list_skips_entries_with_wrong_field_types(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    store = _store(tmp_path)
    _write(store.path, {"profiles": {"demo": payload}})

    assert store.list() == ()


def test_list_skips_non_string_profile_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(
        store,
        "_read_document",
        lambda: {"profiles": {1: {"base_url": "x", "context_type": "nip", "context_value": "1"}}},
    )

    assert store.list() == ()


def test_active_returns_profile(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="123", activate=True)

    assert store.active() == Profile(
        name="demo",
        base_url=KsefEnvironment.DEMO.value,
        context_type="nip",
        context_value="123",
        env="DEMO",
    )


def test_active_is_none_for_orphaned_pointer(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(store.path, {"active_profile": "gone", "profiles": {}})

    assert store.active_name() is None
    assert store.active() is None


def test_active_is_none_for_invalid_active_payload(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(store.path, {"active_profile": "x", "profiles": {"x": "broken"}})

    assert store.active_name() is None


def test_get_returns_profile_and_raises_for_missing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    created = store.create("demo", env="TEST", context_type="nip", context_value="123")

    assert store.get("demo") == created
    with pytest.raises(ProfileError, match="nie istnieje"):
        store.get("other")


def test_read_document_rejects_corrupt_json(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ProfileError, match="nie jest poprawnym JSON-em"):
        store.list()


def test_read_document_rejects_non_object_root(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(store.path, ["not", "an", "object"])

    with pytest.raises(ProfileError, match="musi zawierać obiekt JSON"):
        store.list()


def test_read_document_treats_non_dict_profiles_as_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(store.path, {"version": 1, "profiles": []})

    assert store.list() == ()


def test_read_document_wraps_os_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.path.mkdir(parents=True)

    with pytest.raises(ProfileError, match="Nie można odczytać"):
        store.list()


# --- magazyn: zapis -------------------------------------------------------


def test_create_resolves_environment_and_writes_file(tmp_path: Path) -> None:
    store = _store(tmp_path)

    profile = store.create("demo", env="test", context_type="nip", context_value=" 123 ")

    assert profile.env == "TEST"
    assert profile.base_url == KsefEnvironment.TEST.value
    assert profile.context_value == "123"
    payload = json.loads(store.path.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert payload["profiles"]["demo"]["env"] == "TEST"


def test_create_uses_explicit_base_url_and_env(tmp_path: Path) -> None:
    store = _store(tmp_path)

    profile = store.create(
        "custom",
        base_url="https://example.com/api/",
        env="prod",
        context_type="nip",
        context_value="123",
    )

    assert profile.base_url == "https://example.com/api"
    assert profile.env == "PROD"


def test_create_defaults_to_demo_when_env_missing(tmp_path: Path) -> None:
    store = _store(tmp_path)

    profile = store.create("demo", context_type="nip", context_value="123")

    assert profile.env == "DEMO"
    assert profile.base_url == KsefEnvironment.DEMO.value


def test_create_can_activate(tmp_path: Path) -> None:
    store = _store(tmp_path)

    store.create("demo", env="DEMO", context_type="nip", context_value="1", activate=True)

    assert store.active_name() == "demo"


def test_create_rejects_duplicate(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    with pytest.raises(ProfileError, match="już istnieje"):
        store.create("demo", env="DEMO", context_type="nip", context_value="2")


def test_create_rejects_unknown_environment(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(ProfileError, match="Nieobsługiwane środowisko"):
        store.create("demo", env="UAT", context_type="nip", context_value="1")


@pytest.mark.parametrize("field", ["context_type", "context_value"])
def test_create_rejects_empty_context_fields(tmp_path: Path, field: str) -> None:
    store = _store(tmp_path)
    context_type = "   " if field == "context_type" else "nip"
    context_value = "   " if field == "context_value" else "1"

    with pytest.raises(ProfileError, match=field):
        store.create(
            "demo",
            env="DEMO",
            context_type=context_type,
            context_value=context_value,
        )


def test_create_preserves_unknown_top_level_and_profile_keys(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(
        store.path,
        {
            "version": 1,
            "future_key": {"keep": True},
            "profiles": {
                "demo": {
                    "base_url": KsefEnvironment.DEMO.value,
                    "context_type": "nip",
                    "context_value": "1",
                    "env": "DEMO",
                    "future_profile_key": "keep-me",
                }
            },
        },
    )

    store.update("demo", context_value="2")

    payload = json.loads(store.path.read_text(encoding="utf-8"))
    assert payload["future_key"] == {"keep": True}
    assert payload["profiles"]["demo"]["future_profile_key"] == "keep-me"
    assert payload["profiles"]["demo"]["context_value"] == "2"


def test_update_environment_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    updated = store.update("demo", env="PROD")

    assert updated.env == "PROD"
    assert updated.base_url == KsefEnvironment.PROD.value
    assert updated.context_value == "1"


def test_update_base_url_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    updated = store.update("demo", base_url="https://proxy.example.com")

    assert updated.base_url == "https://proxy.example.com"
    assert updated.env == "DEMO"


def test_update_base_url_with_new_env(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    updated = store.update("demo", base_url="https://proxy.example.com", env="test")

    assert updated.base_url == "https://proxy.example.com"
    assert updated.env == "TEST"


def test_update_context_fields(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    updated = store.update("demo", context_type="pesel", context_value=" 2 ")

    assert updated.context_type == "pesel"
    assert updated.context_value == "2"


def test_update_without_changes_returns_same_profile(tmp_path: Path) -> None:
    store = _store(tmp_path)
    created = store.create("demo", env="DEMO", context_type="nip", context_value="1")

    assert store.update("demo") == created


def test_update_missing_profile_raises(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(ProfileError, match="nie istnieje"):
        store.update("demo", context_value="2")


def test_update_rejects_invalid_stored_payload(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(store.path, {"profiles": {"demo": {"base_url": "x"}}})

    with pytest.raises(ProfileError, match="niepoprawny format"):
        store.update("demo", context_value="2")


@pytest.mark.parametrize("field", ["context_type", "context_value"])
def test_update_rejects_empty_context_fields(tmp_path: Path, field: str) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    with pytest.raises(ProfileError, match=field):
        store.update("demo", **{field: " "})


def test_set_active_switches_profile(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("a", env="DEMO", context_type="nip", context_value="1")
    store.create("b", env="TEST", context_type="nip", context_value="2")

    profile = store.set_active("b")

    assert profile.name == "b"
    assert store.active_name() == "b"


def test_set_active_missing_profile_raises(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(ProfileError, match="nie istnieje"):
        store.set_active("demo")


def test_delete_active_profile_promotes_first_remaining(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("a", env="DEMO", context_type="nip", context_value="1")
    store.create("b", env="TEST", context_type="nip", context_value="2")
    store.set_active("b")

    store.delete("b")

    assert store.active_name() == "a"
    assert store.find("b") is None


def test_delete_last_profile_clears_active(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("only", env="DEMO", context_type="nip", context_value="1", activate=True)

    store.delete("only")

    assert store.active_name() is None
    assert store.list() == ()


def test_delete_missing_profile_raises(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(ProfileError, match="nie istnieje"):
        store.delete("demo")


def test_delete_ignores_invalid_siblings_when_picking_active(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(
        store.path,
        {
            "active_profile": "gone",
            "profiles": {
                "gone": {
                    "base_url": KsefEnvironment.DEMO.value,
                    "context_type": "nip",
                    "context_value": "1",
                },
                "broken": "not-a-dict",
            },
        },
    )

    store.delete("gone")

    assert store.active_name() is None


def test_write_failure_raises_profile_error(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("file", encoding="utf-8")
    store = ProfileStore(blocker / "config.json")

    # Windows zgłasza brak ścieżki (FileNotFoundError) i błąd pojawia się dopiero
    # na mkdir; POSIX zwraca ENOTDIR już przy odczycie. Oba warianty to
    # ProfileError, więc test akceptuje oba komunikaty.
    with pytest.raises(ProfileError, match="Nie można (odczytać|utworzyć katalogu)"):
        store.create("demo", env="DEMO", context_type="nip", context_value="1")


def test_write_document_reports_mkdir_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    def _denied(*_args: object, **_kwargs: object) -> None:
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "mkdir", _denied)

    with pytest.raises(ProfileError, match="Nie można utworzyć katalogu"):
        store.create("other", env="DEMO", context_type="nip", context_value="1")


def test_write_failure_cleans_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    def _fail(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", _fail)

    with pytest.raises(ProfileError, match="Nie można zapisać pliku profili"):
        store.set_active("demo")

    leftovers = [path.name for path in tmp_path.iterdir() if path.name.endswith(".tmp")]
    assert leftovers == []


@pytest.mark.skipif(sys.platform == "win32", reason="uprawnienia POSIX nie dotyczą Windows")
def test_saved_file_has_owner_only_permissions(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    assert store.path.stat().st_mode & 0o777 == 0o600


# --- integracja z opcjami klienta ----------------------------------------


def test_options_from_profile_name(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="TEST", context_type="nip", context_value="1")

    options = KsefClientOptions.from_profile("demo", store=store, timeout_seconds=3.0)

    assert options.base_url == KsefEnvironment.TEST.value
    assert options.timeout_seconds == 3.0


def test_options_from_profile_object() -> None:
    profile = Profile("demo", KsefEnvironment.DEMO.value, "nip", "1")

    options = KsefClientOptions.from_profile(profile)

    assert options.base_url == KsefEnvironment.DEMO.value


def test_options_from_profile_allows_overrides() -> None:
    profile = Profile("demo", KsefEnvironment.DEMO.value, "nip", "1")

    options = KsefClientOptions.from_profile(profile, base_url="https://example.com")

    assert options.base_url == "https://example.com"


def test_options_from_missing_profile_raises(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(ProfileError, match="nie istnieje"):
        KsefClientOptions.from_profile("demo", store=store)


def test_active_name_is_none_for_invalid_dict_payload(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(store.path, {"active_profile": "x", "profiles": {"x": {"base_url": 5}}})

    assert store.active_name() is None
    assert store.active() is None


def test_delete_promotes_first_valid_profile_skipping_invalid(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _write(
        store.path,
        {
            "active_profile": "gone",
            "profiles": {
                "gone": {
                    "base_url": KsefEnvironment.DEMO.value,
                    "context_type": "nip",
                    "context_value": "1",
                },
                "a": {
                    "base_url": KsefEnvironment.TEST.value,
                    "context_type": "nip",
                    "context_value": "2",
                },
                "broken": {"base_url": 5},
            },
        },
    )

    store.delete("gone")

    assert store.active_name() == "a"
    assert store.active() is not None


# --- review 2: współbieżność, env=None, uprawnienia, dekodowanie -----------


def test_update_env_none_clears_label_without_changing_url(tmp_path: Path) -> None:
    store = _store(tmp_path)
    created = store.create("demo", env="TEST", context_type="nip", context_value="1")

    updated = store.update("demo", env=None)

    assert updated.env is None
    assert updated.base_url == created.base_url
    assert store.get("demo").env is None


def test_write_detects_concurrent_modification(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("demo", env="DEMO", context_type="nip", context_value="1")
    document, fingerprint = store._read_state()

    payload = json.loads(store.path.read_text(encoding="utf-8"))
    payload["active_profile"] = "demo"
    _write(store.path, payload)

    with pytest.raises(ProfileError, match="zmieniony przez inny proces"):
        store._write_document(document, expected_fingerprint=fingerprint)


def test_read_state_rejects_invalid_utf8(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(ProfileError, match="nie jest poprawnym JSON-em"):
        store.list()


def test_fingerprint_wraps_os_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.path.mkdir(parents=True)

    with pytest.raises(ProfileError, match="Nie można odczytać"):
        store._fingerprint()


@pytest.mark.skipif(sys.platform == "win32", reason="uprawnienia POSIX nie dotyczą Windows")
def test_config_directory_is_owner_only(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config-dir" / "config.json")
    store.create("demo", env="DEMO", context_type="nip", context_value="1")

    assert (tmp_path / "config-dir").stat().st_mode & 0o777 == 0o700
