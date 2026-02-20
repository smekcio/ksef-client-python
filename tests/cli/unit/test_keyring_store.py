from __future__ import annotations

import importlib
import json
import sys
import threading
import time
import types

import pytest

from ksef_client.cli.auth import keyring_store
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_keyring_store_roundtrip_file_fallback(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")

    keyring_store.save_tokens("demo", "acc", "ref")
    fallback_path = tmp_path / "tokens.json"
    assert fallback_path.exists()
    assert keyring_store.get_tokens("demo") == ("acc", "ref")

    keyring_store.clear_tokens("demo")
    assert keyring_store.get_tokens("demo") is None
    payload = json.loads(fallback_path.read_text(encoding="utf-8"))
    assert payload == {}


def test_keyring_store_roundtrip_encrypted_fallback(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setenv(keyring_store._TOKEN_STORE_KEY_ENV, "my-secret-passphrase")
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)

    keyring_store.save_tokens("demo", "acc", "ref")
    fallback_path = tmp_path / "tokens.json"
    saved = fallback_path.read_text(encoding="utf-8")
    assert '"acc"' not in saved
    assert '"ref"' not in saved
    assert "fernet-v1" in saved
    assert keyring_store.get_tokens("demo") == ("acc", "ref")


def test_keyring_store_file_fallback_save_error(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")
    monkeypatch.setattr(
        keyring_store,
        "_save_fallback_tokens",
        lambda payload: (_ for _ in ()).throw(OSError("disk")),
    )

    with pytest.raises(CliError) as exc:
        keyring_store.save_tokens("demo", "acc", "ref")
    assert exc.value.code == ExitCode.CONFIG_ERROR


def test_keyring_store_file_fallback_save_error_encrypted_mode(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setenv(keyring_store._TOKEN_STORE_KEY_ENV, "my-secret-passphrase")
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)
    monkeypatch.setattr(
        keyring_store,
        "_save_fallback_tokens",
        lambda payload: (_ for _ in ()).throw(OSError("disk")),
    )

    with pytest.raises(CliError) as exc:
        keyring_store.save_tokens("demo", "acc", "ref")
    assert exc.value.code == ExitCode.CONFIG_ERROR


def test_keyring_store_file_fallback_get_handles_invalid_payload(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")

    fallback_path = tmp_path / "tokens.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    fallback_path.write_text("{broken", encoding="utf-8")
    assert keyring_store.get_tokens("demo") is None

    fallback_path.write_text(json.dumps(["bad"]), encoding="utf-8")
    assert keyring_store.get_tokens("demo") is None

    fallback_path.write_text(json.dumps({"demo": "bad"}), encoding="utf-8")
    assert keyring_store.get_tokens("demo") is None

    fallback_path.write_text(json.dumps({"demo": {"access_token": "acc"}}), encoding="utf-8")
    assert keyring_store.get_tokens("demo") is None

    fallback_path.write_text(
        json.dumps(
            {
                "demo": {
                    "access_token": "acc",
                    "refresh_token": "ref",
                }
            }
        ),
        encoding="utf-8",
    )
    assert keyring_store.get_tokens("demo") == ("acc", "ref")


def test_keyring_store_encrypted_fallback_invalid_token(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setenv(keyring_store._TOKEN_STORE_KEY_ENV, "my-secret-passphrase")
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)

    (tmp_path / "tokens.json").write_text(
        json.dumps({"demo": {"enc": "fernet-v1", "access_token": "bad", "refresh_token": "bad"}}),
        encoding="utf-8",
    )
    assert keyring_store.get_tokens("demo") is None


def test_keyring_store_file_fallback_clear_ignores_save_errors(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")
    keyring_store.save_tokens("demo", "acc", "ref")
    monkeypatch.setattr(
        keyring_store,
        "_save_fallback_tokens",
        lambda payload: (_ for _ in ()).throw(OSError("disk")),
    )
    keyring_store.clear_tokens("demo")


def test_keyring_store_clear_tokens_removes_legacy_fallback_entry_when_mode_disabled(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")

    keyring_store.save_tokens("legacy", "acc", "ref")
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)
    monkeypatch.delenv(keyring_store._TOKEN_STORE_KEY_ENV, raising=False)

    keyring_store.clear_tokens("legacy")
    payload = json.loads((tmp_path / "tokens.json").read_text(encoding="utf-8"))
    assert payload == {}


def test_keyring_store_fallback_save_uses_atomic_replace(monkeypatch, tmp_path) -> None:
    replace_targets: list[object] = []
    original_replace = keyring_store.os.replace

    def _tracked_replace(src, dst):
        _ = src
        replace_targets.append(dst)
        return original_replace(src, dst)

    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "replace", _tracked_replace)
    keyring_store._save_fallback_tokens({"demo": {"access_token": "a", "refresh_token": "r"}})

    assert replace_targets == [tmp_path / "tokens.json"]


def test_keyring_store_fallback_save_replace_error_cleans_temp_file(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(
        keyring_store.os,
        "replace",
        lambda src, dst: (_ for _ in ()).throw(OSError(f"{src}->{dst}")),
    )

    with pytest.raises(OSError):
        keyring_store._save_fallback_tokens({"demo": {"access_token": "a", "refresh_token": "r"}})

    assert not [path for path in tmp_path.iterdir() if path.suffix == ".tmp"]


def test_keyring_store_file_fallback_recovers_from_corrupted_payload(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")

    fallback_path = tmp_path / "tokens.json"
    fallback_path.write_text("{broken", encoding="utf-8")

    keyring_store.save_tokens("demo", "acc", "ref")
    assert keyring_store.get_tokens("demo") == ("acc", "ref")
    payload = json.loads(fallback_path.read_text(encoding="utf-8"))
    assert payload == {"demo": {"access_token": "acc", "refresh_token": "ref"}}


def test_keyring_store_file_fallback_waits_for_existing_lock(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")

    lock_path = tmp_path / "tokens.json.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = keyring_store.os.open(
        lock_path, keyring_store.os.O_CREAT | keyring_store.os.O_EXCL | keyring_store.os.O_RDWR
    )

    def _release_lock() -> None:
        time.sleep(0.1)
        keyring_store.os.close(lock_handle)
        lock_path.unlink()

    releaser = threading.Thread(target=_release_lock)
    releaser.start()
    try:
        keyring_store.save_tokens("demo", "acc", "ref")
    finally:
        releaser.join()

    assert keyring_store.get_tokens("demo") == ("acc", "ref")


def test_keyring_store_fallback_lock_timeout(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store, "_FALLBACK_LOCK_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(keyring_store, "_FALLBACK_LOCK_POLL_INTERVAL_SECONDS", 0.0)

    lock_path = tmp_path / "tokens.json.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = keyring_store.os.open(
        lock_path, keyring_store.os.O_CREAT | keyring_store.os.O_EXCL | keyring_store.os.O_RDWR
    )
    try:
        with pytest.raises(OSError), keyring_store._fallback_tokens_lock():
            pass
    finally:
        keyring_store.os.close(lock_handle)
        lock_path.unlink()


def test_keyring_store_update_fallback_tokens_delete_missing_profile_is_noop(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    tokens_path = tmp_path / "tokens.json"
    tokens_path.write_text(
        json.dumps({"demo": {"access_token": "a", "refresh_token": "r"}}),
        encoding="utf-8",
    )

    save_called = {"value": False}

    def _save(payload: dict[str, dict[str, str]]) -> None:
        _ = payload
        save_called["value"] = True

    monkeypatch.setattr(keyring_store, "_save_fallback_tokens", _save)
    keyring_store._update_fallback_tokens("missing", None)
    assert save_called["value"] is False


def test_keyring_store_file_fallback_posix_chmod_error_is_suppressed(monkeypatch, tmp_path) -> None:
    chmod_called = {"value": False}

    def _chmod(path, mode):
        _ = (path, mode)
        chmod_called["value"] = True
        raise OSError("chmod failed")

    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setattr(keyring_store.os, "chmod", _chmod)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")

    keyring_store._save_fallback_tokens({"demo": {"access_token": "a", "refresh_token": "r"}})
    assert chmod_called["value"] is True


def test_keyring_store_keyring_backend_success(monkeypatch) -> None:
    class FakeKeyring:
        def __init__(self) -> None:
            self.store: dict[tuple[str, str], str] = {}

        def set_password(self, service: str, key: str, value: str) -> None:
            self.store[(service, key)] = value

        def get_password(self, service: str, key: str) -> str | None:
            return self.store.get((service, key))

        def delete_password(self, service: str, key: str) -> None:
            self.store.pop((service, key), None)

    fake = FakeKeyring()
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", True)
    monkeypatch.setattr(keyring_store, "_keyring", fake)

    keyring_store.save_tokens("demo", "a1", "r1")
    assert keyring_store.get_tokens("demo") == ("a1", "r1")
    keyring_store.clear_tokens("demo")
    assert keyring_store.get_tokens("demo") is None


def test_keyring_store_keyring_backend_errors(monkeypatch) -> None:
    class FakeKeyringError(Exception):
        pass

    class BrokenKeyring:
        def set_password(self, service: str, key: str, value: str) -> None:
            _ = (service, key, value)
            raise FakeKeyringError("set")

        def get_password(self, service: str, key: str) -> str | None:
            _ = (service, key)
            raise FakeKeyringError("get")

        def delete_password(self, service: str, key: str) -> None:
            _ = (service, key)
            raise FakeKeyringError("delete")

    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", True)
    monkeypatch.setattr(keyring_store, "_keyring", BrokenKeyring())
    monkeypatch.setattr(keyring_store, "KeyringError", FakeKeyringError)
    monkeypatch.delenv(keyring_store._TOKEN_STORE_KEY_ENV, raising=False)
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)

    with pytest.raises(CliError):
        keyring_store.save_tokens("demo", "a", "r")

    # get path should swallow backend errors and return None
    assert keyring_store.get_tokens("demo") is None

    # clear path should swallow backend errors
    keyring_store.clear_tokens("demo")


def test_keyring_store_keyring_error_uses_encrypted_fallback(monkeypatch, tmp_path) -> None:
    class FakeKeyringError(Exception):
        pass

    class BrokenKeyring:
        def set_password(self, service: str, key: str, value: str) -> None:
            _ = (service, key, value)
            raise FakeKeyringError("set")

        def get_password(self, service: str, key: str) -> str:
            _ = (service, key)
            raise FakeKeyringError("get")

        def delete_password(self, service: str, key: str) -> None:
            _ = (service, key)
            raise FakeKeyringError("delete")

    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", True)
    monkeypatch.setattr(keyring_store, "_keyring", BrokenKeyring())
    monkeypatch.setattr(keyring_store, "KeyringError", FakeKeyringError)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setenv(keyring_store._TOKEN_STORE_KEY_ENV, "my-secret-passphrase")
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)

    keyring_store.save_tokens("demo", "acc", "ref")
    saved = (tmp_path / "tokens.json").read_text(encoding="utf-8")
    assert "fernet-v1" in saved
    assert keyring_store.get_tokens("demo") == ("acc", "ref")


def test_keyring_store_blocks_insecure_fallback_by_default(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)

    with pytest.raises(CliError) as exc:
        keyring_store.save_tokens("demo", "acc", "ref")
    assert exc.value.code == ExitCode.CONFIG_ERROR
    assert keyring_store.get_tokens("demo") is None


def test_keyring_store_fallback_cipher_requires_key(monkeypatch) -> None:
    monkeypatch.delenv(keyring_store._TOKEN_STORE_KEY_ENV, raising=False)
    with pytest.raises(CliError) as exc:
        keyring_store._fallback_cipher()
    assert exc.value.code == ExitCode.CONFIG_ERROR


def test_keyring_store_decode_plaintext_rejected_when_insecure_disabled(monkeypatch) -> None:
    monkeypatch.delenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, raising=False)
    result = keyring_store._decode_tokens({"access_token": "acc", "refresh_token": "ref"})
    assert result is None


def test_keyring_store_get_tokens_rejects_empty_decoded_values(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "posix", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")
    (tmp_path / "tokens.json").write_text(
        json.dumps({"demo": {"access_token": "acc", "refresh_token": "ref"}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(keyring_store, "_decode_tokens", lambda data: ("", "ref"))

    assert keyring_store.get_tokens("demo") is None


def test_keyring_store_blocks_plaintext_fallback_on_windows(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", False)
    monkeypatch.setattr(keyring_store, "_keyring", None)
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(keyring_store.os, "name", "nt", raising=False)
    monkeypatch.setenv(keyring_store._ALLOW_INSECURE_FALLBACK_ENV, "1")
    monkeypatch.delenv(keyring_store._TOKEN_STORE_KEY_ENV, raising=False)

    with pytest.raises(CliError) as exc:
        keyring_store.save_tokens("demo", "acc", "ref")
    assert exc.value.code == ExitCode.CONFIG_ERROR
    assert keyring_store._decode_tokens({"access_token": "acc", "refresh_token": "ref"}) is None


def test_keyring_store_import_branch_with_fake_keyring_module(monkeypatch) -> None:
    module_name = "ksef_client.cli.auth.keyring_store"
    original_module = importlib.import_module(module_name)

    fake_keyring = types.ModuleType("keyring")
    fake_errors = types.ModuleType("keyring.errors")

    class FakeKeyringError(Exception):
        pass

    class FakeBackend:
        def set_password(self, service: str, key: str, value: str) -> None:
            _ = (service, key, value)

        def get_password(self, service: str, key: str) -> str | None:
            _ = (service, key)
            return None

        def delete_password(self, service: str, key: str) -> None:
            _ = (service, key)

    backend = FakeBackend()
    fake_keyring.set_password = backend.set_password  # type: ignore[attr-defined]
    fake_keyring.get_password = backend.get_password  # type: ignore[attr-defined]
    fake_keyring.delete_password = backend.delete_password  # type: ignore[attr-defined]
    fake_errors.KeyringError = FakeKeyringError  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    monkeypatch.setitem(sys.modules, "keyring.errors", fake_errors)

    reloaded = importlib.reload(original_module)
    try:
        assert reloaded._KEYRING_AVAILABLE is True
    finally:
        importlib.reload(original_module)
