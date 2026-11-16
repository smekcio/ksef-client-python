"""Live TEST smoke for changing the signing identity between worker cycles."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ksef_client import Ksef, KsefClientOptions, KsefEnvironment
from ksef_client.certificate_rotation import ProfileCertificates
from ksef_client.certificates import FileCertificateStore
from ksef_client.profiles import Profile
from tests.test_e2e_token_flows import (
    _ensure_e2e_enabled,
    _load_test_xades_config,
    _with_rate_limit_retry,
)

pytestmark = pytest.mark.e2e


def _replacement_for_test(certificate_pem: bytes) -> tuple[bytes, rsa.RSAPrivateKey]:
    # KSeF TEST accepts self-signed seals with certificate-chain verification
    # disabled. Keep the configured subject, generate an independent key.
    original = x509.load_pem_x509_certificate(certificate_pem)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM), key


def _current_auth_session(client: Ksef) -> str:
    sessions = _with_rate_limit_retry(client.api.auth.get_active_sessions)
    [current] = [item for item in sessions.items if item.is_current]
    assert current.status.code == 200
    return current.reference_number


def test_e2e_test_environment_certificate_rotation_between_cycles(tmp_path):
    _ensure_e2e_enabled()
    config = _load_test_xades_config()
    options = KsefClientOptions(base_url=config.base_url)
    assert options.normalized_base_url() == f"{KsefEnvironment.TEST.value}/v2"
    assert config.subject_identifier_type == "certificateSubject"
    assert config.certificate_pem and config.private_key_pem
    original_pem = config.certificate_pem.encode()
    original_key = serialization.load_pem_private_key(
        config.private_key_pem.encode(), password=None
    )
    assert isinstance(original_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
    replacement_pem, replacement_key = _replacement_for_test(original_pem)
    profile = Profile("rotation-test", config.base_url, config.context_type, config.context_value)
    store = FileCertificateStore(tmp_path / "certificates", require_password=True)
    selector_path = tmp_path / "selection.db"
    passwords = {name: secrets.token_urlsafe(24) for name in ("original", "replacement")}

    def selector():
        return ProfileCertificates(
            selector_path, profile, store=store, verify_certificate_chain=False
        )

    for name, certificate, key in (
        ("original", original_pem, original_key),
        ("replacement", replacement_pem, replacement_key),
    ):
        store.save(
            name,
            certificate=certificate,
            private_key=key,
            environment="TEST",
            password=passwords[name],
        )

    opened_with = []

    def password_for(name):
        opened_with.append(name)
        return passwords[name]

    original = selector().activate(
        "original",
        expected_generation=0,
        password=passwords["original"],
        verify=_current_auth_session,
    )
    with selector().session(password_for=password_for) as old_cycle:
        old_session = _current_auth_session(old_cycle)
        replacement = selector().activate(
            "replacement",
            expected_generation=original.generation,
            password=passwords["replacement"],
            verify=_current_auth_session,
        )
        assert replacement.generation == original.generation + 1
        assert replacement.fingerprint_sha256 != original.fingerprint_sha256
        assert _current_auth_session(old_cycle) == old_session
        assert selector().status().selection == replacement
        with selector().session(password_for=password_for) as new_cycle:
            assert _current_auth_session(new_cycle) != old_session

    assert opened_with == ["original", "replacement"]
