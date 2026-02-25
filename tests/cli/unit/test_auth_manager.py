from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from ksef_client.cli.auth import manager
from ksef_client.cli.config.schema import CliConfig, ProfileConfig
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.config import KsefLighthouseEnvironment


class _FakeClient:
    def __init__(self) -> None:
        self.security = SimpleNamespace(
            get_public_key_certificates=lambda: [
                {"usage": ["KsefTokenEncryption"], "certificate": "CERT"},
            ]
        )
        self.auth = SimpleNamespace(
            refresh_access_token=lambda refresh: {
                "accessToken": {"token": "new", "validUntil": "v2"}
            }
        )

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)


@dataclass
class _FakeTokens:
    access_token: SimpleNamespace
    refresh_token: SimpleNamespace


@dataclass
class _FakeAuthResult:
    reference_number: str
    tokens: _FakeTokens


class _FakeAuthCoordinator:
    def __init__(self, _auth) -> None:
        _ = _auth

    def authenticate_with_ksef_token(self, **kwargs) -> _FakeAuthResult:
        _ = kwargs
        return _FakeAuthResult(
            reference_number="ref-1",
            tokens=_FakeTokens(
                access_token=SimpleNamespace(token="acc", valid_until="v1"),
                refresh_token=SimpleNamespace(token="ref", valid_until="v2"),
            ),
        )

    def authenticate_with_xades_key_pair(self, **kwargs) -> _FakeAuthResult:
        _ = kwargs
        return _FakeAuthResult(
            reference_number="xades-ref-1",
            tokens=_FakeTokens(
                access_token=SimpleNamespace(token="x-acc", valid_until="x-v1"),
                refresh_token=SimpleNamespace(token="x-ref", valid_until="x-v2"),
            ),
        )


def test_login_with_token_success(monkeypatch) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)

    saved: dict[str, str] = {}
    monkeypatch.setattr(
        manager,
        "save_tokens",
        lambda profile, access, refresh: saved.update(
            {"profile": profile, "access": access, "refresh": refresh}
        ),
    )
    monkeypatch.setattr(
        manager, "set_cached_metadata", lambda profile, metadata: saved.update(metadata)
    )

    result = manager.login_with_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        token="TOKEN",
        context_type="nip",
        context_value="5265877635",
        poll_interval=0.0,
        max_attempts=1,
        save=True,
    )

    assert result["reference_number"] == "ref-1"
    assert saved["profile"] == "demo"
    assert saved["access"] == "acc"


def test_login_with_token_uses_profile_context_fallback(monkeypatch) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)
    monkeypatch.setattr(
        manager,
        "load_config",
        lambda: CliConfig(
            active_profile="demo",
            profiles={
                "demo": ProfileConfig(
                    name="demo",
                    env="DEMO",
                    base_url="https://api-demo.ksef.mf.gov.pl",
                    context_type="nip",
                    context_value="5265877635",
                )
            },
        ),
    )
    monkeypatch.setattr(manager, "save_tokens", lambda profile, access, refresh: None)
    monkeypatch.setattr(manager, "set_cached_metadata", lambda profile, metadata: None)

    result = manager.login_with_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        token="TOKEN",
        context_type="",
        context_value="",
        poll_interval=0.0,
        max_attempts=1,
        save=True,
    )
    assert result["reference_number"] == "ref-1"


def test_refresh_access_token_requires_tokens(monkeypatch) -> None:
    monkeypatch.setattr(manager, "get_tokens", lambda profile: None)
    with pytest.raises(CliError) as exc:
        manager.refresh_access_token(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            save=True,
        )
    assert exc.value.code == ExitCode.AUTH_ERROR


def test_refresh_access_token_success(monkeypatch) -> None:
    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "save_tokens", lambda profile, access, refresh: None)
    monkeypatch.setattr(manager, "get_cached_metadata", lambda profile: {"method": "token"})
    monkeypatch.setattr(manager, "set_cached_metadata", lambda profile, metadata: None)

    result = manager.refresh_access_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        save=True,
    )

    assert result["access_valid_until"] == "v2"


def test_status_and_logout(monkeypatch) -> None:
    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "get_cached_metadata", lambda profile: {"method": "token"})
    status = manager.get_auth_status("demo")
    assert status["has_tokens"] is True

    called = {"tokens": False, "cache": False}
    monkeypatch.setattr(manager, "clear_tokens", lambda profile: called.__setitem__("tokens", True))
    monkeypatch.setattr(
        manager, "clear_cached_metadata", lambda profile: called.__setitem__("cache", True)
    )
    result = manager.logout("demo")
    assert result["logged_out"] is True
    assert called["tokens"] and called["cache"]


def test_select_certificate_and_require_non_empty_errors() -> None:
    with pytest.raises(CliError) as cert_error:
        manager._select_certificate([], "KsefTokenEncryption")
    assert cert_error.value.code == ExitCode.API_ERROR

    with pytest.raises(CliError) as value_error:
        manager._require_non_empty("  ", "msg", "hint")
    assert value_error.value.code == ExitCode.VALIDATION_ERROR


def test_resolve_base_url_prefers_provided_value() -> None:
    assert manager.resolve_base_url(" https://api.example ") == "https://api.example"
    assert manager.resolve_base_url(None).startswith("https://")


def test_resolve_base_url_uses_profile_when_missing(monkeypatch) -> None:
    monkeypatch.setattr(
        manager,
        "load_config",
        lambda: CliConfig(
            active_profile="demo",
            profiles={
                "demo": ProfileConfig(
                    name="demo",
                    env="DEMO",
                    base_url="https://profile.example",
                    context_type="nip",
                    context_value="123",
                )
            },
        ),
    )
    assert manager.resolve_base_url(None, profile="demo") == "https://profile.example"


def test_resolve_lighthouse_base_url_prefers_explicit_value() -> None:
    assert manager.resolve_lighthouse_base_url(" https://api-latarnia-test.ksef.mf.gov.pl/ ") == (
        "https://api-latarnia-test.ksef.mf.gov.pl/"
    ).strip()


def test_resolve_lighthouse_base_url_uses_profile_mapping(monkeypatch) -> None:
    monkeypatch.setattr(
        manager,
        "load_config",
        lambda: CliConfig(
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
        ),
    )
    assert manager.resolve_lighthouse_base_url(None, profile="demo") == (
        KsefLighthouseEnvironment.TEST.value
    )


def test_resolve_lighthouse_base_url_fallbacks_to_lighthouse_test(monkeypatch) -> None:
    monkeypatch.setattr(manager, "load_config", lambda: CliConfig())
    assert manager.resolve_lighthouse_base_url(None) == KsefLighthouseEnvironment.TEST.value


def test_resolve_lighthouse_base_url_invalid_profile_base_fallback(monkeypatch) -> None:
    monkeypatch.setattr(
        manager,
        "load_config",
        lambda: CliConfig(
            active_profile="demo",
            profiles={
                "demo": ProfileConfig(
                    name="demo",
                    env="DEMO",
                    base_url="https://unknown.example",
                    context_type="nip",
                    context_value="123",
                )
            },
        ),
    )
    assert manager.resolve_lighthouse_base_url(None, profile="demo") == (
        KsefLighthouseEnvironment.TEST.value
    )


def test_refresh_access_token_missing_token_in_response(monkeypatch) -> None:
    class _FakeClientNoToken:
        def __init__(self) -> None:
            self.auth = SimpleNamespace(refresh_access_token=lambda refresh: {"accessToken": {}})

        def __enter__(self) -> _FakeClientNoToken:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            _ = (exc_type, exc, tb)

    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClientNoToken())

    with pytest.raises(CliError) as exc:
        manager.refresh_access_token(
            profile="demo", base_url="https://api-demo.ksef.mf.gov.pl", save=False
        )
    assert exc.value.code == ExitCode.API_ERROR


def test_login_with_xades_pkcs12_success(monkeypatch) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)

    class _FakeKeyPair:
        pass

    monkeypatch.setattr(
        manager.XadesKeyPair,
        "from_pkcs12_file",
        lambda **kwargs: _FakeKeyPair(),
    )
    saved: dict[str, str] = {}
    monkeypatch.setattr(
        manager,
        "save_tokens",
        lambda profile, access, refresh: saved.update(
            {"profile": profile, "access": access, "refresh": refresh}
        ),
    )
    monkeypatch.setattr(
        manager, "set_cached_metadata", lambda profile, metadata: saved.update(metadata)
    )

    result = manager.login_with_xades(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        context_type="nip",
        context_value="5265877635",
        pkcs12_path="cert.p12",
        pkcs12_password="pwd",
        cert_pem=None,
        key_pem=None,
        key_password=None,
        subject_identifier_type="certificateSubject",
        poll_interval=0.0,
        max_attempts=1,
        save=True,
    )
    assert result["reference_number"] == "xades-ref-1"
    assert saved["access"] == "x-acc"


def test_login_with_xades_pem_pair_success_without_save(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("CERT", encoding="utf-8")
    key.write_text("KEY", encoding="utf-8")

    class _FakeKeyPair:
        pass

    monkeypatch.setattr(
        manager.XadesKeyPair,
        "from_pem_files",
        lambda **kwargs: _FakeKeyPair(),
    )

    result = manager.login_with_xades(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        context_type="nip",
        context_value="5265877635",
        pkcs12_path=None,
        pkcs12_password=None,
        cert_pem=str(cert),
        key_pem=str(key),
        key_password=None,
        subject_identifier_type="certificateFingerprint",
        poll_interval=0.0,
        max_attempts=1,
        save=False,
    )
    assert result["saved"] is False


def test_login_with_xades_validation_paths(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)

    with pytest.raises(CliError) as both_sources:
        manager.login_with_xades(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            context_type="nip",
            context_value="5265877635",
            pkcs12_path="cert.p12",
            pkcs12_password=None,
            cert_pem="cert.pem",
            key_pem="key.pem",
            key_password=None,
            subject_identifier_type="certificateSubject",
            poll_interval=0.0,
            max_attempts=1,
            save=False,
        )
    assert both_sources.value.code == ExitCode.VALIDATION_ERROR

    with pytest.raises(CliError) as no_sources:
        manager.login_with_xades(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            context_type="nip",
            context_value="5265877635",
            pkcs12_path=None,
            pkcs12_password=None,
            cert_pem=None,
            key_pem=None,
            key_password=None,
            subject_identifier_type="certificateSubject",
            poll_interval=0.0,
            max_attempts=1,
            save=False,
        )
    assert no_sources.value.code == ExitCode.VALIDATION_ERROR

    with pytest.raises(CliError) as invalid_subject:
        manager.login_with_xades(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            context_type="nip",
            context_value="5265877635",
            pkcs12_path="cert.p12",
            pkcs12_password=None,
            cert_pem=None,
            key_pem=None,
            key_password=None,
            subject_identifier_type="bad",
            poll_interval=0.0,
            max_attempts=1,
            save=False,
        )
    assert invalid_subject.value.code == ExitCode.VALIDATION_ERROR

    with pytest.raises(CliError) as missing_cert_file:
        manager.login_with_xades(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            context_type="nip",
            context_value="5265877635",
            pkcs12_path=None,
            pkcs12_password=None,
            cert_pem=str(tmp_path / "missing-cert.pem"),
            key_pem=str(tmp_path / "missing-key.pem"),
            key_password=None,
            subject_identifier_type="certificateSubject",
            poll_interval=0.0,
            max_attempts=1,
            save=False,
        )
    assert missing_cert_file.value.code == ExitCode.VALIDATION_ERROR

    cert = tmp_path / "cert.pem"
    cert.write_text("CERT", encoding="utf-8")
    with pytest.raises(CliError) as missing_key_file:
        manager.login_with_xades(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            context_type="nip",
            context_value="5265877635",
            pkcs12_path=None,
            pkcs12_password=None,
            cert_pem=str(cert),
            key_pem=str(tmp_path / "missing-key.pem"),
            key_password=None,
            subject_identifier_type="certificateSubject",
            poll_interval=0.0,
            max_attempts=1,
            save=False,
        )
    assert missing_key_file.value.code == ExitCode.VALIDATION_ERROR


def test_login_with_xades_loader_errors_are_mapped(monkeypatch) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)
    monkeypatch.setattr(
        manager.XadesKeyPair,
        "from_pkcs12_file",
        lambda **kwargs: (_ for _ in ()).throw(ValueError("bad file")),
    )

    with pytest.raises(CliError) as exc:
        manager.login_with_xades(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            context_type="nip",
            context_value="5265877635",
            pkcs12_path="cert.p12",
            pkcs12_password=None,
            cert_pem=None,
            key_pem=None,
            key_password=None,
            subject_identifier_type="certificateSubject",
            poll_interval=0.0,
            max_attempts=1,
            save=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR
