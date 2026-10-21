from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from ksef_client.certificates import (
    CertificateRecord,
    CertificateStore,
    CertificateStoreError,
    FileCertificateStore,
    StoredCertificate,
)

_NOW = datetime.now(timezone.utc)


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _certificate(key: object, *, common_name: str = "KSeF Test") -> x509.Certificate:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        ]
    )
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())  # type: ignore[attr-defined]
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(hours=1))
        .not_valid_after(_NOW + timedelta(days=365))
        .sign(key, algorithm)  # type: ignore[arg-type]
    )


@pytest.fixture(scope="module")
def rsa_pair() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    return _certificate(key), key


@pytest.fixture()
def store(tmp_path: Path) -> FileCertificateStore:
    return FileCertificateStore(tmp_path / "certificates")


def _pem_certificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: object, password: bytes | None = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


# --- zapis i odczyt -------------------------------------------------------


def test_save_and_load_roundtrip(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair

    record = store.save("prod", certificate=certificate, private_key=key, environment="PROD")
    loaded = store.load("prod")

    assert isinstance(record, CertificateRecord)
    assert record.name == "prod"
    assert record.subject == certificate.subject.rfc4514_string()
    assert record.serial_number == format(certificate.serial_number, "x")
    assert record.environment == "PROD"
    assert record.has_password is False
    assert record.created_at is not None
    assert isinstance(loaded, StoredCertificate)
    assert loaded.certificate == certificate
    assert loaded.record == record
    assert loaded.certificate_pem == _pem_certificate(certificate)
    assert loaded.key_pair()[0] == certificate
    assert loaded.private_key.private_numbers() == key.private_numbers()


def test_save_accepts_pem_strings(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair

    store.save(
        "pem",
        certificate=_pem_certificate(certificate).decode("ascii"),
        private_key=_pem_key(key).decode("ascii"),
    )

    assert store.load("pem").certificate == certificate


def test_save_accepts_pem_bytes(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair

    store.save("bytes", certificate=_pem_certificate(certificate), private_key=_pem_key(key))

    assert store.load("bytes").record.name == "bytes"


def test_save_supports_ec_keys(store: FileCertificateStore) -> None:
    key = _ec_key()
    certificate = _certificate(key)

    store.save("ec", certificate=certificate, private_key=key)

    assert isinstance(store.load("ec").private_key, ec.EllipticCurvePrivateKey)


def test_save_encrypts_key_with_password(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair

    record = store.save("secure", certificate=certificate, private_key=key, password="secret")

    assert record.has_password is True
    loaded = store.load("secure", password="secret")
    assert loaded.certificate == certificate
    assert loaded.private_key.private_numbers() == key.private_numbers()


def test_load_encrypted_key_without_password_fails(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("secure", certificate=certificate, private_key=key, password=b"secret")

    with pytest.raises(CertificateStoreError, match="podaj hasło"):
        store.load("secure")


def test_load_with_wrong_password_fails(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("secure", certificate=certificate, private_key=key, password="secret")

    with pytest.raises(CertificateStoreError, match="Nie można odszyfrować"):
        store.load("secure", password="wrong")


def test_record_does_not_require_password_for_encrypted_key(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("secure", certificate=certificate, private_key=key, password="secret")

    record = store.record("secure")

    assert record.has_password is True


def test_save_rejects_duplicate_without_overwrite(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)

    with pytest.raises(CertificateStoreError, match="już istnieje"):
        store.save("prod", certificate=certificate, private_key=key)


def test_save_overwrites_when_requested(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    other_key = _key()
    other_certificate = _certificate(other_key, common_name="Other")

    record = store.save(
        "prod",
        certificate=other_certificate,
        private_key=other_key,
        overwrite=True,
    )

    assert record.subject == other_certificate.subject.rfc4514_string()
    assert store.load("prod").certificate == other_certificate


def test_save_rejects_mismatched_pair(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, _ = rsa_pair
    other_key = _key()

    with pytest.raises(CertificateStoreError, match="nie pasuje do certyfikatu"):
        store.save("bad", certificate=certificate, private_key=other_key)


@pytest.mark.parametrize("name", ["", "  ", "..", "a/b", "a\\b", "x" * 65, "zażółć"])
def test_save_rejects_invalid_names(store: FileCertificateStore, name: str) -> None:
    with pytest.raises(CertificateStoreError):
        store.save(name, certificate=b"x", private_key=b"y")


def test_save_rejects_non_string_name(store: FileCertificateStore) -> None:
    with pytest.raises(CertificateStoreError, match="musi być tekstem"):
        store.save(1, certificate=b"x", private_key=b"y")  # type: ignore[arg-type]


def test_save_rejects_invalid_certificate(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    _, key = rsa_pair

    with pytest.raises(CertificateStoreError, match="Nie można sparsować certyfikatu"):
        store.save("bad", certificate=b"not a pem", private_key=key)


def test_save_rejects_unsupported_certificate_type(store: FileCertificateStore) -> None:
    with pytest.raises(CertificateStoreError, match="Certyfikat musi być"):
        store.save("bad", certificate=123, private_key=b"x")  # type: ignore[arg-type]


def test_save_rejects_invalid_key(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, _ = rsa_pair

    with pytest.raises(CertificateStoreError, match="Nie można sparsować klucza"):
        store.save("bad", certificate=certificate, private_key=b"not a key")


def test_save_rejects_unsupported_key_type(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, _ = rsa_pair

    with pytest.raises(CertificateStoreError, match="Klucz prywatny musi być"):
        store.save("bad", certificate=certificate, private_key=123)  # type: ignore[arg-type]


def test_save_rejects_ed25519_key(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, _ = rsa_pair
    key = ed25519.Ed25519PrivateKey.generate()

    with pytest.raises(CertificateStoreError, match="Klucz prywatny musi być"):
        store.save("ed", certificate=certificate, private_key=key)  # type: ignore[arg-type]


def test_save_rejects_ed25519_pem_key(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, _ = rsa_pair
    key = ed25519.Ed25519PrivateKey.generate()

    with pytest.raises(CertificateStoreError, match="Wymagany RSA albo EC"):
        store.save("ed", certificate=certificate, private_key=_pem_key(key))


def test_save_rejects_encrypted_key_without_password(store: FileCertificateStore) -> None:
    key = _key()
    certificate = _certificate(key)

    with pytest.raises(CertificateStoreError, match="podaj hasło"):
        store.save(
            "enc",
            certificate=certificate,
            private_key=_pem_key(key, b"secret"),
        )


@pytest.mark.parametrize("password", ["", b""])
def test_save_rejects_empty_password(store: FileCertificateStore, password: str | bytes) -> None:
    with pytest.raises(CertificateStoreError, match="Hasło nie może być puste"):
        store.save("x", certificate=b"x", private_key=b"y", password=password)


def test_save_rejects_non_text_password(store: FileCertificateStore) -> None:
    with pytest.raises(CertificateStoreError, match="Hasło musi być tekstem"):
        store.save("x", certificate=b"x", private_key=b"y", password=123)  # type: ignore[arg-type]


# --- listowanie, usuwanie, istnienie --------------------------------------


def test_exists_and_delete(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    assert store.exists("prod") is False
    store.save("prod", certificate=certificate, private_key=key)

    assert store.exists("prod") is True
    store.delete("prod")
    assert store.exists("prod") is False


def test_delete_missing_entry_fails(store: FileCertificateStore) -> None:
    with pytest.raises(CertificateStoreError, match="nie istnieje"):
        store.delete("prod")


def test_delete_fails_when_directory_contains_subdirectory(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    (store.directory / "prod" / "nested").mkdir()

    with pytest.raises(CertificateStoreError, match="Nie można usunąć"):
        store.delete("prod")


def test_list_is_empty_for_missing_directory(tmp_path: Path) -> None:
    assert FileCertificateStore(tmp_path / "missing").list() == ()


def test_list_returns_sorted_records(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("b", certificate=certificate, private_key=key)
    store.save("a", certificate=certificate, private_key=key)

    assert [record.name for record in store.list()] == ["a", "b"]


def test_list_skips_files_invalid_names_and_entries_without_certificate(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("good", certificate=certificate, private_key=key)
    store.directory.mkdir(parents=True, exist_ok=True)
    (store.directory / "loose-file").write_text("x", encoding="utf-8")
    (store.directory / "bad name").mkdir()
    (store.directory / "empty").mkdir()

    assert [record.name for record in store.list()] == ["good"]


def test_list_warns_and_skips_corrupt_certificate(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("broken", certificate=certificate, private_key=key)
    (store.directory / "broken" / "cert.pem").write_bytes(b"not a pem")

    with pytest.warns(RuntimeWarning, match="Pomijam uszkodzony certyfikat"):
        records = store.list()

    assert records == ()


def test_load_missing_entry_fails(store: FileCertificateStore) -> None:
    with pytest.raises(CertificateStoreError, match="nie istnieje"):
        store.load("prod")


def test_record_missing_entry_fails(store: FileCertificateStore) -> None:
    with pytest.raises(CertificateStoreError, match="nie istnieje"):
        store.record("prod")


def test_load_incomplete_entry_fails(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    (store.directory / "prod" / "key.pem").unlink()

    with pytest.raises(CertificateStoreError, match="niekompletny"):
        store.load("prod")


def test_record_incomplete_entry_fails(store: FileCertificateStore) -> None:
    (store.directory / "prod").mkdir(parents=True)

    with pytest.raises(CertificateStoreError, match="niekompletny"):
        store.record("prod")


def test_load_corrupt_certificate_fails(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    (store.directory / "prod" / "cert.pem").write_bytes(b"not a pem")

    with pytest.raises(CertificateStoreError, match="niepoprawny plik cert.pem"):
        store.load("prod")


def test_load_rejects_unsupported_key_type(
    store: FileCertificateStore,
) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    certificate = _certificate(key)
    entry = store.directory / "ed"
    entry.mkdir(parents=True)
    (entry / "cert.pem").write_bytes(_pem_certificate(certificate))
    (entry / "key.pem").write_bytes(_pem_key(key))

    with pytest.raises(CertificateStoreError, match="Nieobsługiwany typ klucza w 'ed'"):
        store.load("ed")


def test_load_rejects_mismatched_pair_on_disk(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, _ = rsa_pair
    other_key = _key()
    entry = store.directory / "bad"
    entry.mkdir(parents=True)
    (entry / "cert.pem").write_bytes(_pem_certificate(certificate))
    (entry / "key.pem").write_bytes(_pem_key(other_key))

    with pytest.raises(CertificateStoreError, match="nie pasuje do certyfikatu"):
        store.load("bad")


def test_record_handles_corrupt_metadata(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    (store.directory / "prod" / "meta.json").write_text("{not-json", encoding="utf-8")

    record = store.record("prod")

    assert record.environment is None
    assert record.created_at is None


def test_record_handles_metadata_with_wrong_types(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    (store.directory / "prod" / "meta.json").write_text(
        json.dumps({"environment": 5, "created_at": "not-a-date", "has_password": "yes"}),
        encoding="utf-8",
    )

    record = store.record("prod")

    assert record.environment is None
    assert record.created_at is None
    assert record.has_password is False


def test_record_handles_non_object_metadata(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    (store.directory / "prod" / "meta.json").write_text("[]", encoding="utf-8")

    assert store.record("prod").environment is None


def test_record_corrupt_certificate_fails(store: FileCertificateStore) -> None:
    (store.directory / "prod").mkdir(parents=True)
    (store.directory / "prod" / "cert.pem").write_bytes(b"not a pem")

    with pytest.raises(CertificateStoreError, match="niepoprawny plik cert.pem"):
        store.record("prod")


def test_write_file_cleans_up_temporary_file_on_replace_failure(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair

    def _failing_replace(*args: object, **kwargs: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr("ksef_client.certificates.os.replace", _failing_replace)

    with pytest.raises(CertificateStoreError, match="Nie można zapisać certyfikatu"):
        store.save("prod", certificate=certificate, private_key=key)

    assert not (store.directory / "prod").exists()


def test_save_cleans_up_when_write_fails(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    calls = {"count": 0}

    def _failing_write(path: Path, data: bytes) -> None:
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("disk full")
        path.write_bytes(data)

    monkeypatch.setattr(store, "_write_file", _failing_write)

    with pytest.raises(CertificateStoreError, match="Nie można zapisać certyfikatu"):
        store.save("prod", certificate=certificate, private_key=key)

    assert not (store.directory / "prod").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="uprawnienia POSIX nie dotyczą Windows")
def test_saved_files_are_owner_only(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)

    for name in ("cert.pem", "key.pem", "meta.json"):
        assert (store.directory / "prod" / name).stat().st_mode & 0o777 == 0o600


def test_file_store_implements_the_protocol(store: FileCertificateStore) -> None:
    assert isinstance(store, CertificateStore)


def test_default_store_uses_standard_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ksef_client import paths

    monkeypatch.setenv("APPDATA", str(tmp_path))

    assert FileCertificateStore.default().directory == paths.certificates_dir()


def test_stored_certificate_repr_redacts_key_material(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)

    text = repr(store.load("prod"))

    assert "PRIVATE KEY" not in text
    assert "private_key=<redacted>" in text
    assert "private_key_pem=<redacted>" in text


def test_overwrite_failure_restores_previous_pair(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_certificate, old_key = rsa_pair
    store.save("prod", certificate=old_certificate, private_key=old_key)
    new_key = _key()
    new_certificate = _certificate(new_key, common_name="New")

    original_write = store._write_file
    calls = {"count": 0}

    def _failing_write(path: Path, data: bytes) -> None:
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("disk full")
        original_write(path, data)

    monkeypatch.setattr(store, "_write_file", _failing_write)

    with pytest.raises(CertificateStoreError, match="Nie można zapisać certyfikatu"):
        store.save(
            "prod",
            certificate=new_certificate,
            private_key=new_key,
            overwrite=True,
        )

    restored = store.load("prod")
    assert restored.certificate == old_certificate
    assert restored.private_key.private_numbers() == old_key.private_numbers()


def test_delete_wraps_os_error(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)

    def _locked(*_args: object, **_kwargs: object) -> None:
        raise OSError("file is locked")

    monkeypatch.setattr(Path, "unlink", _locked)

    with pytest.raises(CertificateStoreError, match="Nie można usunąć"):
        store.delete("prod")
