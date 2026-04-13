from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from ksef_client import models as m
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
        self.tokens = SimpleNamespace(
            revoke_token=lambda reference_number, access_token: None
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


def _token_list_item(
    *,
    reference_number: str,
    context_type: str = "Nip",
    context_value: str = "5265877635",
) -> m.QueryTokensResponseItem:
    return m.QueryTokensResponseItem(
        author_identifier=m.TokenAuthorIdentifierTypeIdentifier(
            type=m.TokenAuthorIdentifierType.NIP,
            value="5265877635",
        ),
        context_identifier=m.TokenContextIdentifierTypeIdentifier(
            type=m.TokenContextIdentifierType(context_type),
            value=context_value,
        ),
        date_created="2026-04-13T10:00:00Z",
        description="Current token",
        reference_number=reference_number,
        requested_permissions=[],
        status=m.AuthenticationTokenStatus.ACTIVE,
        last_use_date="2026-04-13T10:01:00Z",
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
    assert saved["ksef_token_reference_number"] == ""


def test_discover_current_token_reference_number_skips_mismatched_context(monkeypatch) -> None:
    client = SimpleNamespace(
        tokens=SimpleNamespace(
            list_tokens=lambda **kwargs: m.QueryTokensResponse(
                tokens=[
                    _token_list_item(reference_number="REF-OTHER", context_value="1111111111"),
                    _token_list_item(reference_number="REF-123"),
                ],
                continuation_token=None,
            )
        )
    )
    monkeypatch.setattr(
        manager,
        "_profile_context",
        lambda profile: ("https://api-demo.ksef.mf.gov.pl", "Nip", "5265877635"),
    )

    result = manager._discover_current_token_reference_number(
        client=client,
        access_token="acc",
        profile="demo",
    )

    assert result == "REF-123"


def test_discover_current_token_reference_number_returns_none_for_multiple_matches(
    monkeypatch,
) -> None:
    client = SimpleNamespace(
        tokens=SimpleNamespace(
            list_tokens=lambda **kwargs: m.QueryTokensResponse(
                tokens=[
                    _token_list_item(reference_number="REF-123"),
                    _token_list_item(reference_number="REF-456"),
                ],
                continuation_token=None,
            )
        )
    )
    monkeypatch.setattr(
        manager,
        "_profile_context",
        lambda profile: ("https://api-demo.ksef.mf.gov.pl", "Nip", "5265877635"),
    )

    result = manager._discover_current_token_reference_number(
        client=client,
        access_token="acc",
        profile="demo",
    )

    assert result is None


def test_discover_current_token_reference_number_stops_on_repeated_continuation_token(
    monkeypatch,
) -> None:
    calls: list[str | None] = []

    def _list_tokens(**kwargs) -> m.QueryTokensResponse:
        calls.append(kwargs.get("continuation_token"))
        return m.QueryTokensResponse(tokens=[], continuation_token="next")

    client = SimpleNamespace(tokens=SimpleNamespace(list_tokens=_list_tokens))
    monkeypatch.setattr(
        manager,
        "_profile_context",
        lambda profile: ("https://api-demo.ksef.mf.gov.pl", "Nip", "5265877635"),
    )

    result = manager._discover_current_token_reference_number(
        client=client,
        access_token="acc",
        profile="demo",
    )

    assert result is None
    assert calls == [None, "next"]


def test_login_with_token_caches_ksef_reference_number(monkeypatch) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)

    saved: dict[str, str] = {}
    monkeypatch.setattr(manager, "save_tokens", lambda profile, access, refresh: None)
    monkeypatch.setattr(
        manager, "set_cached_metadata", lambda profile, metadata: saved.update(metadata)
    )

    manager.login_with_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        token="REF-123|internalId-5265877635-12345|secret",
        context_type="nip",
        context_value="5265877635",
        poll_interval=0.0,
        max_attempts=1,
        save=True,
    )

    assert saved["ksef_token_reference_number"] == "REF-123"


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
    cert = manager._select_certificate(
        [
            {"usage": ["KsefTokenEncryption"], "certificate": ""},
            {"usage": ["KsefTokenEncryption"], "certificate": "CERT"},
        ],
        "KsefTokenEncryption",
    )
    assert cert == "CERT"

    with pytest.raises(CliError) as cert_error:
        manager._select_certificate([], "KsefTokenEncryption")
    assert cert_error.value.code == ExitCode.API_ERROR

    with pytest.raises(CliError) as value_error:
        manager._require_non_empty("  ", "msg", "hint")
    assert value_error.value.code == ExitCode.VALIDATION_ERROR


def test_select_certificate_supports_object_payloads() -> None:
    cert = manager._select_certificate(
        [
            SimpleNamespace(
                usage=[SimpleNamespace(value="KsefTokenEncryption")],
                certificate="CERT-OBJ",
            )
        ],
        "KsefTokenEncryption",
    )
    assert cert == "CERT-OBJ"


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


def test_resolve_base_url_falls_back_when_profile_base_url_empty(monkeypatch) -> None:
    monkeypatch.setattr(
        manager,
        "load_config",
        lambda: CliConfig(
            active_profile="demo",
            profiles={
                "demo": ProfileConfig(
                    name="demo",
                    env="DEMO",
                    base_url=" ",
                    context_type="nip",
                    context_value="123",
                )
            },
        ),
    )
    assert manager.resolve_base_url(None, profile="demo") == manager.KsefEnvironment.DEMO.value


def test_resolve_lighthouse_base_url_prefers_explicit_value() -> None:
    assert (
        manager.resolve_lighthouse_base_url(" https://api-latarnia-test.ksef.mf.gov.pl/ ")
        == ("https://api-latarnia-test.ksef.mf.gov.pl/").strip()
    )


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


def test_resolve_lighthouse_base_url_fallback_when_profile_base_url_empty(monkeypatch) -> None:
    monkeypatch.setattr(
        manager,
        "load_config",
        lambda: CliConfig(
            active_profile="demo",
            profiles={
                "demo": ProfileConfig(
                    name="demo",
                    env="DEMO",
                    base_url=" ",
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


def test_login_with_token_without_save(monkeypatch) -> None:
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(manager, "AuthCoordinator", _FakeAuthCoordinator)
    monkeypatch.setattr(
        manager,
        "save_tokens",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("save_tokens should not be called")
        ),
    )
    monkeypatch.setattr(
        manager,
        "set_cached_metadata",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("set_cached_metadata should not be called")
        ),
    )

    result = manager.login_with_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        token="TOKEN",
        context_type="nip",
        context_value="5265877635",
        poll_interval=0.0,
        max_attempts=1,
        save=False,
    )
    assert result["saved"] is False


def test_refresh_access_token_success_without_save(monkeypatch) -> None:
    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeClient())
    monkeypatch.setattr(
        manager,
        "save_tokens",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("save_tokens should not be called")
        ),
    )
    monkeypatch.setattr(
        manager,
        "set_cached_metadata",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("set_cached_metadata should not be called")
        ),
    )

    result = manager.refresh_access_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        save=False,
    )
    assert result["saved"] is False


def test_refresh_access_token_accepts_typed_response(monkeypatch) -> None:
    class _FakeTypedClient:
        def __init__(self) -> None:
            self.auth = SimpleNamespace(
                refresh_access_token=lambda refresh: m.AuthenticationTokenRefreshResponse.from_dict(
                    {"accessToken": {"token": "typed-new", "validUntil": "typed-v2"}}
                )
            )

        def __enter__(self) -> _FakeTypedClient:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            _ = (exc_type, exc, tb)

    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeTypedClient())
    monkeypatch.setattr(manager, "save_tokens", lambda profile, access, refresh: None)
    monkeypatch.setattr(manager, "get_cached_metadata", lambda profile: {"method": "token"})
    monkeypatch.setattr(manager, "set_cached_metadata", lambda profile, metadata: None)

    result = manager.refresh_access_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        save=True,
    )
    assert result["access_valid_until"] == "typed-v2"


def test_refresh_access_token_rejects_unexpected_typed_response(monkeypatch) -> None:
    class _FakeInvalidClient:
        def __init__(self) -> None:
            self.auth = SimpleNamespace(refresh_access_token=lambda refresh: SimpleNamespace())

        def __enter__(self) -> _FakeInvalidClient:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            _ = (exc_type, exc, tb)

    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeInvalidClient())

    with pytest.raises(CliError) as exc:
        manager.refresh_access_token(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
            save=False,
        )
    assert exc.value.code == ExitCode.API_ERROR


def test_revoke_self_token_success(monkeypatch) -> None:
    revoked: dict[str, str] = {}
    cleared = {"tokens": False, "cache": False}

    class _FakeRevokeClient(_FakeClient):
        def __init__(self) -> None:
            super().__init__()
            self.tokens = SimpleNamespace(
                revoke_token=lambda reference_number, access_token: revoked.update(
                    {"reference_number": reference_number, "access_token": access_token}
                )
            )

    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        manager,
        "get_cached_metadata",
        lambda profile: {
            "method": "token",
            "ksef_token_reference_number": "REF-123",
        },
    )
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeRevokeClient())
    monkeypatch.setattr(
        manager, "clear_tokens", lambda profile: cleared.__setitem__("tokens", True)
    )
    monkeypatch.setattr(
        manager, "clear_cached_metadata", lambda profile: cleared.__setitem__("cache", True)
    )

    result = manager.revoke_self_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
    )

    assert revoked == {"reference_number": "REF-123", "access_token": "acc"}
    assert result["revoked"] is True
    assert cleared["tokens"] is True
    assert cleared["cache"] is True


def test_revoke_self_token_falls_back_to_listing_current_token(monkeypatch) -> None:
    revoked: dict[str, str] = {}

    class _FakeListClient(_FakeClient):
        def __init__(self) -> None:
            super().__init__()
            self.tokens = SimpleNamespace(
                list_tokens=lambda **kwargs: m.QueryTokensResponse(
                    tokens=[_token_list_item(reference_number="REF-123")],
                    continuation_token=None,
                ),
                revoke_token=lambda reference_number, access_token: revoked.update(
                    {
                        "reference_number": reference_number,
                        "access_token": access_token,
                    }
                ),
            )

    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        manager,
        "get_cached_metadata",
        lambda profile: {"method": "token"},
    )
    monkeypatch.setattr(
        manager,
        "_profile_context",
        lambda profile: ("https://api-demo.ksef.mf.gov.pl", "Nip", "5265877635"),
    )
    monkeypatch.setattr(manager, "create_client", lambda base_url: _FakeListClient())
    monkeypatch.setattr(manager, "clear_tokens", lambda profile: None)
    monkeypatch.setattr(manager, "clear_cached_metadata", lambda profile: None)

    result = manager.revoke_self_token(
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
    )

    assert revoked == {"reference_number": "REF-123", "access_token": "acc"}
    assert result["reference_number"] == "REF-123"


def test_revoke_self_token_requires_stored_tokens(monkeypatch) -> None:
    monkeypatch.setattr(manager, "get_tokens", lambda profile: None)

    with pytest.raises(CliError) as exc:
        manager.revoke_self_token(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
        )

    assert exc.value.code == ExitCode.AUTH_ERROR


def test_revoke_self_token_requires_token_auth_method(monkeypatch) -> None:
    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "get_cached_metadata", lambda profile: {"method": "xades"})

    with pytest.raises(CliError) as exc:
        manager.revoke_self_token(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
        )

    assert exc.value.code == ExitCode.AUTH_ERROR


def test_revoke_self_token_requires_unambiguous_reference_number(monkeypatch) -> None:
    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(manager, "get_cached_metadata", lambda profile: {"method": "token"})
    monkeypatch.setattr(
        manager,
        "_discover_current_token_reference_number",
        lambda **kwargs: None,
    )

    with pytest.raises(CliError) as exc:
        manager.revoke_self_token(
            profile="demo",
            base_url="https://api-demo.ksef.mf.gov.pl",
        )

    assert exc.value.code == ExitCode.AUTH_ERROR
