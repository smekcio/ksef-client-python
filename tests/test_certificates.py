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


def _certificate(
    key: object,
    *,
    common_name: str = "KSeF Test",
    not_before: datetime = _NOW - timedelta(hours=1),
    not_after: datetime = _NOW + timedelta(days=365),
) -> x509.Certificate:
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
        .not_valid_before(not_before)
        .not_valid_after(not_after)
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


def test_load_rejects_password_for_unencrypted_key(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("plain", certificate=certificate, private_key=key)

    # Klucz jest jawny, więc hasło jest błędem wywołania — komunikat nie może
    # twierdzić, że klucz jest zaszyfrowany (tak było wcześniej).
    with pytest.raises(CertificateStoreError, match="nie jest zaszyfrowany"):
        store.load("plain", password="secret")


def test_save_rejects_password_for_unencrypted_pem_key(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair

    with pytest.raises(CertificateStoreError, match="nie jest zaszyfrowany"):
        store.save("plain", certificate=certificate, private_key=_pem_key(key), password="secret")


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


def test_save_wraps_backup_read_error(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    original = Path.read_bytes

    def failing_read(path: Path) -> bytes:
        if path.name == "cert.pem":
            raise OSError("plik zablokowany")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", failing_read)

    with pytest.raises(CertificateStoreError, match="Nie można odczytać poprzedniego wpisu"):
        store.save("prod", certificate=certificate, private_key=key, overwrite=True)


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


@pytest.mark.parametrize("name", ["", "  ", ".", "..", "prod.", "a/b", "a\\b", "x" * 65, "zażółć"])
def test_save_rejects_invalid_names(store: FileCertificateStore, name: str) -> None:
    with pytest.raises(CertificateStoreError):
        store.save(name, certificate=b"x", private_key=b"y")


def test_dot_name_cannot_target_store_directory(store: FileCertificateStore) -> None:
    # `Path(".")` wskazuje katalog magazynu — `delete(".")` usuwało jego pliki
    # i sam katalog, a `save(".")` pisało klucz do katalogu głównego.
    with pytest.raises(CertificateStoreError, match="Niepoprawna nazwa"):
        store.delete(".")
    with pytest.raises(CertificateStoreError, match="Niepoprawna nazwa"):
        store.exists(".")
    assert not store.directory.exists()


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


@pytest.mark.parametrize("payload", [b"{not json", b"\xff\xfe\x00"])
def test_corrupt_metadata_does_not_break_reading(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    payload: bytes,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key, environment="PROD")
    (store.directory / "prod" / "meta.json").write_bytes(payload)

    # meta.json jest opcjonalny: uszkodzony plik nie może wywracać `list()`
    # ani `record()` (wcześniej leciał `UnicodeDecodeError`).
    records = store.list()
    assert [record.name for record in records] == ["prod"]
    assert records[0].environment is None
    assert store.record("prod").environment is None
    assert store.load("prod").certificate == certificate


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


# --- review 2: hasło, symlinki, kompletność wpisów, uprawnienia -----------


def _fake_symlink(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    original = Path.is_symlink

    def _is_symlink(self: Path) -> bool:
        return self.name == name or original(self)

    monkeypatch.setattr(Path, "is_symlink", _is_symlink)


def test_require_password_blocks_plaintext_key(
    tmp_path: Path, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store = FileCertificateStore(tmp_path / "certs", require_password=True)

    assert store.require_password is True
    with pytest.raises(CertificateStoreError, match="wymaga hasła"):
        store.save("prod", certificate=certificate, private_key=key)

    record = store.save("prod", certificate=certificate, private_key=key, password="secret")

    assert record.has_password is True
    assert store.load("prod", password="secret").certificate == certificate


def test_save_rejects_symlinked_entry(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    _fake_symlink(monkeypatch, "prod")

    with pytest.raises(CertificateStoreError, match="dowiązaniem symbolicznym"):
        store.save("prod", certificate=certificate, private_key=key)


def test_load_rejects_symlinked_entry(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    _fake_symlink(monkeypatch, "prod")

    with pytest.raises(CertificateStoreError, match="dowiązaniem symbolicznym"):
        store.load("prod")


def test_delete_rejects_symlinked_entry(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    _fake_symlink(monkeypatch, "prod")

    with pytest.raises(CertificateStoreError, match="dowiązaniem symbolicznym"):
        store.delete("prod")


def test_record_rejects_symlinked_entry(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    _fake_symlink(monkeypatch, "prod")

    with pytest.raises(CertificateStoreError, match="dowiązaniem symbolicznym"):
        store.record("prod")


def test_exists_returns_false_for_symlinked_entry(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    _fake_symlink(monkeypatch, "prod")

    assert store.exists("prod") is False


def test_list_skips_symlinked_entry(
    store: FileCertificateStore,
    rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    _fake_symlink(monkeypatch, "prod")

    assert store.list() == ()


def test_list_skips_entry_without_key(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)
    (store.directory / "prod" / "key.pem").unlink()

    with pytest.warns(RuntimeWarning, match="brak key.pem"):
        records = store.list()

    assert records == ()


@pytest.mark.skipif(sys.platform == "win32", reason="uprawnienia POSIX nie dotyczą Windows")
def test_store_directories_are_owner_only(
    store: FileCertificateStore, rsa_pair: tuple[x509.Certificate, rsa.RSAPrivateKey]
) -> None:
    certificate, key = rsa_pair
    store.save("prod", certificate=certificate, private_key=key)

    assert store.directory.stat().st_mode & 0o777 == 0o700
    assert (store.directory / "prod").stat().st_mode & 0o777 == 0o700


def test_profile_rotation_verifies_before_switch_and_preserves_in_flight_client(
    tmp_path, store, rsa_pair, monkeypatch
):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from typing import cast

    from ksef_client.certificate_rotation import CertificateRotationError, ProfileCertificates
    from ksef_client.config import KsefEnvironment
    from ksef_client.facade import Ksef
    from ksef_client.profiles import Profile

    profile = Profile("worker", KsefEnvironment.TEST.value, "nip", "123", "TEST")
    first, key = rsa_pair
    second = _certificate(key, common_name="Rotated")
    store.save("first", certificate=first, private_key=key, environment="TEST")
    store.save("second", certificate=second, private_key=key, environment="TEST")
    selector = ProfileCertificates(tmp_path / "certificate-selector.db", profile, store=store)

    def connect(*, credentials, profile, timeout):
        assert profile.context_value == "123"
        return nullcontext(
            SimpleNamespace(
                pem=credentials.key_pair.certificate_pem,
                api=SimpleNamespace(auth=SimpleNamespace(revoke_current_session=lambda: None)),
            )
        )

    monkeypatch.setattr(Ksef, "connect", connect)
    initial = selector.activate("first", expected_generation=0)
    assert selector.status().selection == initial
    with selector.connect() as old_worker:
        rotated = selector.activate("second", expected_generation=initial.generation)
        assert selector.status().selection == rotated
        with selector.connect() as new_worker:
            assert cast(SimpleNamespace, new_worker).pem == _pem_certificate(second).decode()
        assert cast(SimpleNamespace, old_worker).pem == _pem_certificate(first).decode()
    with pytest.raises(CertificateRotationError, match="changed"):
        selector.activate("first", expected_generation=initial.generation)


def test_failed_candidate_and_concurrent_rotation_keep_working_selection(
    tmp_path, store, rsa_pair, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import nullcontext
    from threading import Barrier
    from types import SimpleNamespace

    from ksef_client.certificate_rotation import CertificateRotationError, ProfileCertificates
    from ksef_client.config import KsefEnvironment
    from ksef_client.facade import Ksef
    from ksef_client.profiles import Profile

    profile = Profile("worker", KsefEnvironment.TEST.value, "nip", "123", "TEST")
    for name in ("initial", "candidate-a", "candidate-b"):
        cert, key = rsa_pair
        store.save(name, certificate=cert, private_key=key, environment="TEST", password=name)
    selector = ProfileCertificates(tmp_path / "selector.db", profile, store=store)
    assert selector.status().status == "unconfigured"
    with pytest.raises(CertificateRotationError, match="No active"):
        selector.connect()

    def connect(**kwargs):
        return nullcontext(
            SimpleNamespace(
                api=SimpleNamespace(auth=SimpleNamespace(revoke_current_session=lambda: None)),
            )
        )

    monkeypatch.setattr(Ksef, "connect", connect)
    initial = selector.activate("initial", expected_generation=0, password="initial")
    assert selector.status(warn_before=timedelta(days=365)).status == "expiring"

    def rejected(_client):
        raise RuntimeError("Required permission missing")

    with pytest.raises(RuntimeError, match="Required permission"):
        selector.activate(
            "candidate-a", expected_generation=1, password="candidate-a", verify=rejected
        )
    assert selector.status().selection == initial
    barrier = Barrier(2)

    def verify_candidate(_client) -> None:
        barrier.wait(timeout=5)

    def rotate(name):
        try:
            return selector.activate(
                name,
                expected_generation=1,
                password=name,
                subject_identifier_type="certificateFingerprint",
                verify=verify_candidate,
            )
        except CertificateRotationError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(rotate, ("candidate-a", "candidate-b")))
    successes = [selection for selection in results if selection is not None]
    assert len(successes) == 1
    active = successes[0]
    assert active.generation == 2
    assert active.subject_identifier_type == "certificateFingerprint"
    assert selector.status().selection == active
    with selector.connect(password_for=lambda name: name):
        pass
    store.delete(active.name)
    assert selector.status().status == "unavailable"


@pytest.fixture
def profile_certificate_selector(tmp_path, store):
    from ksef_client.certificate_rotation import ProfileCertificates
    from ksef_client.config import KsefEnvironment
    from ksef_client.profiles import Profile

    profile = Profile("worker", KsefEnvironment.TEST.value, "nip", "123", "TEST")
    return ProfileCertificates(tmp_path / "selector.db", profile, store=store)


def test_rotation_reports_invalid_configuration_and_selector_io(
    tmp_path, store, profile_certificate_selector, monkeypatch
):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from ksef_client import certificate_rotation
    from ksef_client.certificate_rotation import CertificateRotationError, ProfileCertificates
    from ksef_client.profiles import Profile

    with pytest.raises(CertificateRotationError, match="HTTPS"):
        ProfileCertificates(
            tmp_path / "bad.db", Profile("worker", "http://proxy.invalid", "nip", "123")
        )
    selector = profile_certificate_selector
    with pytest.raises(ValueError, match="non-negative"):
        selector.status(warn_before=timedelta(seconds=-1))
    with pytest.raises(ValueError, match="non-negative integer"):
        selector.activate("candidate", expected_generation=True)
    with pytest.raises(ValueError, match="subject identifier"):
        selector.activate("candidate", expected_generation=0, subject_identifier_type="other")
    connection = Mock()
    connection.execute.side_effect = OSError("could not initialize database")
    monkeypatch.setattr(
        certificate_rotation, "sqlite3", SimpleNamespace(connect=lambda _: connection)
    )
    with pytest.raises(OSError, match="could not initialize"):
        selector.status()
    connection.close.assert_called_once()
    path = tmp_path / "unsafe.db"
    path.mkdir()
    unsafe = ProfileCertificates(
        path, Profile("worker", "https://proxy.invalid", "nip", "123"), store=store
    )
    with pytest.raises(CertificateRotationError, match="Unsafe"):
        unsafe.status()


@pytest.mark.parametrize(
    ("not_before", "not_after", "status"),
    [
        (_NOW - timedelta(days=2), _NOW - timedelta(days=1), "expired"),
        (_NOW + timedelta(days=1), _NOW + timedelta(days=2), "not_yet_valid"),
    ],
)
def test_rotation_rejects_unusable_x509_validity(
    store, profile_certificate_selector, rsa_pair, not_before, not_after, status
):
    from ksef_client.certificate_rotation import CertificateRotationError

    _, key = rsa_pair
    candidate = _certificate(key, not_before=not_before, not_after=not_after)
    store.save("candidate", certificate=candidate, private_key=key)
    with pytest.raises(CertificateRotationError, match=status):
        profile_certificate_selector.activate("candidate", expected_generation=0)


def test_rotation_rejects_wrong_environment_and_requires_configured_encryption(
    tmp_path, store, profile_certificate_selector, rsa_pair
):
    from ksef_client.certificate_rotation import CertificateRotationError, ProfileCertificates
    from ksef_client.config import KsefEnvironment
    from ksef_client.profiles import Profile

    cert, key = rsa_pair
    store.save("prod-only", certificate=cert, private_key=key, environment="PROD")
    with pytest.raises(CertificateRotationError, match="environment"):
        profile_certificate_selector.activate("prod-only", expected_generation=0)
    profile = Profile("worker", KsefEnvironment.TEST.value, "nip", "123")
    encrypted = FileCertificateStore(store.directory, require_password=True)
    selector = ProfileCertificates(tmp_path / "other-selector.db", profile, store=encrypted)
    with pytest.raises(CertificateRotationError, match="requires a key password"):
        selector.activate("prod-only", expected_generation=0)


def test_rotation_keeps_previous_version_if_candidate_changes_or_key_is_missing(
    store, profile_certificate_selector, rsa_pair, monkeypatch
):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from ksef_client.certificate_rotation import CertificateRotationError
    from ksef_client.facade import Ksef

    cert, key = rsa_pair
    different = _certificate(key, common_name="Replacement")
    store.save("old", certificate=cert, private_key=key)
    store.save("candidate", certificate=cert, private_key=key)
    client = SimpleNamespace(
        api=SimpleNamespace(auth=SimpleNamespace(revoke_current_session=lambda: None))
    )
    monkeypatch.setattr(Ksef, "connect", lambda **kwargs: nullcontext(client))
    selector = profile_certificate_selector
    previous = selector.activate("old", expected_generation=0)

    def replace_candidate(_client) -> None:
        store.save("candidate", certificate=different, private_key=key, overwrite=True)

    with pytest.raises(CertificateRotationError, match="fingerprint changed"):
        selector.activate("candidate", expected_generation=1, verify=replace_candidate)
    assert selector.status().selection == previous

    store.save("old", certificate=different, private_key=key, overwrite=True)
    assert selector.status().status == "fingerprint_mismatch"
    with pytest.raises(CertificateRotationError, match="fingerprint changed"):
        selector.connect()
    (store.directory / "old" / "key.pem").unlink()
    assert selector.status().status == "unavailable"


def test_rotation_session_cleanup_does_not_mask_business_error(
    store, profile_certificate_selector, rsa_pair, monkeypatch, caplog
):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from ksef_client.exceptions import KsefHttpError
    from ksef_client.facade import Ksef

    cert, key = rsa_pair
    store.save("active", certificate=cert, private_key=key)
    revocations = []

    def revoke():
        revocations.append(True)
        if len(revocations) == 2:
            raise KsefHttpError(503, "sensitive response detail")

    client = SimpleNamespace(
        api=SimpleNamespace(auth=SimpleNamespace(revoke_current_session=revoke))
    )
    monkeypatch.setattr(Ksef, "connect", lambda **kwargs: nullcontext(client))
    selector = profile_certificate_selector
    selector.activate("active", expected_generation=0)
    with pytest.raises(ValueError, match="worker failed"), selector.session():
        raise ValueError("worker failed")
    assert len(revocations) == 2
    assert "Could not revoke the temporary XAdES session" in caplog.text
    assert "sensitive response detail" not in caplog.text
    with pytest.raises(ValueError, match="version-specific password"):
        selector.connect(password="first", password_for=lambda name: "second")


@pytest.mark.parametrize("name", ["invalid/name", " name-with-whitespace"])
def test_selection_validates_database_record_before_password_provider(
    profile_certificate_selector, name
):
    from contextlib import closing
    from unittest.mock import Mock

    from ksef_client.certificate_rotation import CertificateRotationError

    selector = profile_certificate_selector
    with closing(selector._open()) as connection, connection:
        connection.execute(
            "INSERT INTO certificate_selection VALUES (?, ?, ?, ?, ?)",
            (selector._scope, "valid-name", "invalid", 1, "certificateSubject"),
        )
    callback = Mock()
    with pytest.raises(CertificateRotationError, match="Invalid stored certificate selection"):
        selector.connect(password_for=callback)
    with closing(selector._open()) as connection, connection:
        connection.execute(
            "UPDATE certificate_selection SET name = ?, fingerprint = ?",
            (name, "a" * 64),
        )
    with pytest.raises(CertificateRotationError, match="Invalid stored certificate name"):
        selector.connect(password_for=callback)
    callback.assert_not_called()


@pytest.mark.parametrize(
    "invalid_policy", [{"verify_certificate_chain": "true"}, {"enforce_xades_compliance": 1}]
)
def test_rotation_preserves_xades_policy_across_activation_and_connect(
    tmp_path, store, rsa_pair, monkeypatch, invalid_policy
):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from ksef_client.certificate_rotation import ProfileCertificates
    from ksef_client.config import KsefEnvironment
    from ksef_client.facade import Ksef
    from ksef_client.profiles import Profile

    profile = Profile("worker", KsefEnvironment.TEST.value, "nip", "123", "TEST")
    path = tmp_path / "selector.db"
    store.save("first", certificate=rsa_pair[0], private_key=rsa_pair[1], environment="TEST")
    with pytest.raises(TypeError):
        ProfileCertificates(path, profile, store=store, **invalid_policy)
    selector = ProfileCertificates(
        path, profile, store=store, verify_certificate_chain=True, enforce_xades_compliance=True
    )
    calls = []

    def connect(*, credentials, profile, timeout):
        calls.append((credentials.verify_certificate_chain, credentials.enforce_xades_compliance))
        return nullcontext(
            SimpleNamespace(
                api=SimpleNamespace(auth=SimpleNamespace(revoke_current_session=lambda: None)),
            )
        )

    monkeypatch.setattr(Ksef, "connect", connect)
    selector.activate("first", expected_generation=0)
    with selector.session():
        pass
    assert calls == [(True, True), (True, True)]
    assert ProfileCertificates(path, profile, store=store).status().status == "unconfigured"
