"""Magazyn certyfikatów XAdES dla SDK.

CLI trzyma tokeny w keyringu, ale certyfikatów XAdES nie przechowuje wcale —
użytkownik podaje ścieżki przy każdym logowaniu. Ten moduł daje SDK odpowiednik
magazynu: nazwany zestaw „certyfikat + klucz prywatny”, zapisany na dysku
z uprawnieniami ``0600`` i metadanymi (subject, odcisk SHA-256, okres ważności).

```python
from ksef_client.certificates import FileCertificateStore

store = FileCertificateStore.default()
store.save("prod-2026", certificate=cert_pem, private_key=key_pem)
credentials = store.load("prod-2026")
```

Magazyn **nie** jest zamkiem sejfu: klucz prywatny leży na dysku w formacie PEM
(opcjonalnie zaszyfrowany hasłem). Chroni go ACL systemu plików i uprawnienia
``0600``; hasło nigdy nie jest zapisywane obok klucza.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import warnings
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    load_pem_private_key,
)

from . import paths

#: Klucze obsługiwane przez XAdES w KSeF (RSA i EC).
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

#: Nazwa certyfikatu jest segmentem ścieżki — bez separatorów i ``..``.
_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

_CERT_FILE = "cert.pem"
_KEY_FILE = "key.pem"
_META_FILE = "meta.json"


class CertificateStoreError(ValueError):
    """Błąd magazynu certyfikatów (nazwa, format, para klucz/cert, hasło)."""


@dataclass(frozen=True)
class CertificateRecord:
    """Metadane zapisanego certyfikatu (bez materiału klucza).

    Attributes:
        name: Nazwa wpisu w magazynie.
        subject: DN certyfikatu w formacie RFC 4514.
        serial_number: Numer seryjny w zapisie szesnastkowym.
        not_valid_before: Początek ważności (UTC).
        not_valid_after: Koniec ważności (UTC).
        fingerprint_sha256: Odcisk SHA-256 certyfikatu (hex).
        environment: Opcjonalna etykieta środowiska (``TEST``/``DEMO``/``PROD``).
        created_at: Kiedy wpis zapisano (UTC).
        has_password: Czy klucz prywatny jest zaszyfrowany hasłem.
    """

    name: str
    subject: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    fingerprint_sha256: str
    environment: str | None = None
    created_at: datetime | None = None
    has_password: bool = False


@dataclass(frozen=True, repr=False)
class StoredCertificate:
    """Certyfikat wraz z kluczem prywatnym odczytany z magazynu.

    Attributes:
        record: Metadane wpisu.
        certificate: Sparsowany certyfikat X.509.
        private_key: Klucz prywatny (RSA albo EC).
        certificate_pem: Bajty PEM certyfikatu (do przekazania do API).
        private_key_pem: Bajty PEM klucza (zaszyfrowane, jeśli użyto hasła).
    """

    record: CertificateRecord
    certificate: x509.Certificate
    private_key: PrivateKey
    certificate_pem: bytes
    private_key_pem: bytes

    def __repr__(self) -> str:
        """Reprezentacja bez materiału klucza.

        Domyślny ``repr`` dataclass wypisywał ``private_key_pem`` w całości,
        więc jedno ``print(credentials)`` albo log wyjątku z obiektem w danych
        wynosił klucz prywatny do logów. Ten sam standard stosuje reszta SDK
        (tokeny i klucze są poza ``repr``).
        """
        return (
            f"StoredCertificate(record={self.record!r}, "
            "certificate=<x509.Certificate>, private_key=<redacted>, "
            "private_key_pem=<redacted>)"
        )

    def key_pair(self) -> tuple[x509.Certificate, PrivateKey]:
        """Zwraca parę ``(certyfikat, klucz)`` do podpisu XAdES."""
        return self.certificate, self.private_key


@runtime_checkable
class CertificateStore(Protocol):
    """Interfejs magazynu certyfikatów.

    SDK korzysta wyłącznie z tego protokołu, więc można podstawić własną
    implementację (np. Vault, KMS, baza danych) bez zmiany reszty kodu.
    """

    def save(
        self,
        name: str,
        *,
        certificate: x509.Certificate | bytes | str,
        private_key: PrivateKey | bytes | str,
        password: str | bytes | None = None,
        environment: str | None = None,
        overwrite: bool = False,
    ) -> CertificateRecord:
        """Zapisuje parę certyfikat + klucz pod nazwą."""

    def load(self, name: str, *, password: str | bytes | None = None) -> StoredCertificate:
        """Odczytuje parę certyfikat + klucz."""

    def list(self) -> tuple[CertificateRecord, ...]:
        """Zwraca metadane wszystkich wpisów."""

    def delete(self, name: str) -> None:
        """Usuwa wpis."""

    def exists(self, name: str) -> bool:
        """Czy wpis istnieje."""


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise CertificateStoreError(
            f"Nazwa certyfikatu musi być tekstem, otrzymano {type(name).__name__}."
        )
    normalized = name.strip()
    if not normalized:
        raise CertificateStoreError("Nazwa certyfikatu nie może być pusta.")
    if not _NAME_RE.fullmatch(normalized) or ".." in normalized:
        raise CertificateStoreError(
            f"Niepoprawna nazwa certyfikatu: {name!r}. "
            "Dozwolone są litery, cyfry, '_', '-' i '.' (bez '..'), np. 'prod-2026'."
        )
    return normalized


def _password_bytes(password: str | bytes | None) -> bytes | None:
    if password is None:
        return None
    if isinstance(password, str):
        if not password:
            raise CertificateStoreError(
                "Hasło nie może być puste — pomiń parametr, aby go nie używać."
            )
        return password.encode("utf-8")
    if isinstance(password, bytes):
        if not password:
            raise CertificateStoreError(
                "Hasło nie może być puste — pomiń parametr, aby go nie używać."
            )
        return password
    raise CertificateStoreError(
        f"Hasło musi być tekstem albo bajtami, otrzymano {type(password).__name__}."
    )


def _coerce_certificate(certificate: x509.Certificate | bytes | str) -> x509.Certificate:
    if isinstance(certificate, x509.Certificate):
        return certificate
    if isinstance(certificate, str):
        data = certificate.encode("utf-8")
    elif isinstance(certificate, bytes):
        data = certificate
    else:
        raise CertificateStoreError(
            "Certyfikat musi być obiektem x509.Certificate albo danymi PEM, "
            f"otrzymano {type(certificate).__name__}."
        )
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise CertificateStoreError(f"Nie można sparsować certyfikatu PEM: {exc}") from exc


def _coerce_private_key(
    private_key: PrivateKey | bytes | str,
    *,
    password: bytes | None,
) -> PrivateKey:
    if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        return private_key
    if isinstance(private_key, str):
        data = private_key.encode("utf-8")
    elif isinstance(private_key, bytes):
        data = private_key
    else:
        raise CertificateStoreError(
            "Klucz prywatny musi być obiektem klucza RSA/EC albo danymi PEM, "
            f"otrzymano {type(private_key).__name__}."
        )
    try:
        loaded = load_pem_private_key(data, password=password)
    except TypeError as exc:
        raise CertificateStoreError(
            "Klucz prywatny jest zaszyfrowany — podaj hasło w parametrze 'password'."
        ) from exc
    except ValueError as exc:
        raise CertificateStoreError(f"Nie można sparsować klucza prywatnego PEM: {exc}") from exc
    if not isinstance(loaded, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise CertificateStoreError(
            f"Nieobsługiwany typ klucza: {type(loaded).__name__}. Wymagany RSA albo EC."
        )
    return loaded


def _public_bytes(value: PrivateKey | x509.Certificate) -> bytes:
    return value.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _ensure_pair(certificate: x509.Certificate, private_key: PrivateKey) -> None:
    if _public_bytes(certificate) != _public_bytes(private_key):
        raise CertificateStoreError(
            "Klucz prywatny nie pasuje do certyfikatu (różne klucze publiczne). "
            "Sprawdź, czy pliki pochodzą z tej samej pary."
        )


def _record(
    name: str,
    certificate: x509.Certificate,
    *,
    environment: str | None,
    created_at: datetime | None,
    has_password: bool,
) -> CertificateRecord:
    return CertificateRecord(
        name=name,
        subject=certificate.subject.rfc4514_string(),
        serial_number=format(certificate.serial_number, "x"),
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        environment=environment,
        created_at=created_at,
        has_password=has_password,
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FileCertificateStore:
    """Magazyn certyfikatów w katalogu na dysku.

    Układ wpisu::

        <katalog>/<nazwa>/cert.pem    # 0600
        <katalog>/<nazwa>/key.pem     # 0600, opcjonalnie zaszyfrowany
        <katalog>/<nazwa>/meta.json   # 0600, metadane wpisu

    Args:
        directory: Katalog magazynu. ``None`` oznacza
            :func:`ksef_client.paths.certificates_dir`.
        require_password: Gdy ``True``, :meth:`save` odmawia zapisu klucza bez
            hasła. Domyślnie ``False`` (klucz chroniony ACL systemu plików),
            ale w środowisku produkcyjnym warto włączyć ten tryb.
    """

    def __init__(
        self,
        directory: str | Path | None = None,
        *,
        require_password: bool = False,
    ) -> None:
        self._directory = Path(directory) if directory is not None else paths.certificates_dir()
        self._require_password = require_password

    @property
    def directory(self) -> Path:
        """Katalog, w którym magazyn trzyma wpisy."""
        return self._directory

    @property
    def require_password(self) -> bool:
        """Czy magazyn wymaga hasła do klucza prywatnego."""
        return self._require_password

    @classmethod
    def default(cls) -> FileCertificateStore:
        """Magazyn w standardowej lokalizacji."""
        return cls()

    def _entry_dir(self, name: str) -> Path:
        return self._directory / name

    @staticmethod
    def _reject_symlink(name: str, entry: Path) -> None:
        """Odmawia operacji na wpisie będącym dowiązaniem symbolicznym.

        Nazwa jest walidowana, więc nie da się wyjść poza katalog nazwą, ale
        podstawiony symlink ``<katalog>/<nazwa>`` przekierowałby zapis i odczyt
        poza magazyn. Wymaga to prawa zapisu w katalogu konfiguracji, czyli
        zwykle tych samych uprawnień co dostęp do klucza — mimo to lepiej
        odmówić niż pisać przez link.
        """
        if entry.is_symlink():
            raise CertificateStoreError(
                f"Wpis '{name}' jest dowiązaniem symbolicznym — operacja odmówiona."
            )

    def _read_meta(self, entry: Path) -> dict[str, object]:
        meta_path = entry / _META_FILE
        try:
            raw = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def _write_file(self, path: Path, data: bytes) -> None:
        temp_path: Path | None = None
        try:
            descriptor, temp_name = tempfile.mkstemp(
                dir=path.parent,
                prefix=f"{path.name}.",
                suffix=".tmp",
            )
            temp_path = Path(temp_name)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            with suppress(OSError):
                os.chmod(temp_path, 0o600)
            os.replace(temp_path, path)
            temp_path = None
        finally:
            if temp_path is not None:
                with suppress(OSError):
                    temp_path.unlink(missing_ok=True)

    def save(
        self,
        name: str,
        *,
        certificate: x509.Certificate | bytes | str,
        private_key: PrivateKey | bytes | str,
        password: str | bytes | None = None,
        environment: str | None = None,
        overwrite: bool = False,
    ) -> CertificateRecord:
        """Zapisuje certyfikat i klucz pod nazwą.

        Args:
            name: Nazwa wpisu.
            certificate: Certyfikat (obiekt albo PEM).
            private_key: Klucz prywatny (obiekt albo PEM; może być zaszyfrowany).
            password: Hasło do zaszyfrowania klucza przy zapisie. ``None``
                zapisuje klucz bez szyfrowania.
            environment: Opcjonalna etykieta środowiska.
            overwrite: Czy nadpisać istniejący wpis.

        Returns:
            Metadane zapisanego wpisu.

        Raises:
            CertificateStoreError: Gdy nazwa jest niepoprawna, wpis istnieje,
                dane się nie parsują albo klucz nie pasuje do certyfikatu.
        """
        normalized = _validate_name(name)
        entry = self._entry_dir(normalized)
        self._reject_symlink(normalized, entry)
        if entry.exists() and not overwrite:
            raise CertificateStoreError(
                f"Certyfikat '{normalized}' już istnieje. Użyj overwrite=True, aby go nadpisać."
            )
        password_bytes = _password_bytes(password)
        if self._require_password and password_bytes is None:
            raise CertificateStoreError(
                f"Magazyn wymaga hasła do klucza: zapis '{normalized}' bez password "
                "jest zablokowany (require_password=True)."
            )
        parsed_certificate = _coerce_certificate(certificate)
        parsed_key = _coerce_private_key(private_key, password=password_bytes)
        _ensure_pair(parsed_certificate, parsed_key)

        certificate_pem = parsed_certificate.public_bytes(serialization.Encoding.PEM)
        encryption = (
            BestAvailableEncryption(password_bytes)
            if password_bytes is not None
            else NoEncryption()
        )
        private_key_pem = parsed_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        created_at = _utc_now()
        record = _record(
            normalized,
            parsed_certificate,
            environment=environment,
            created_at=created_at,
            has_password=password_bytes is not None,
        )
        meta = {
            "name": record.name,
            "subject": record.subject,
            "serial_number": record.serial_number,
            "not_valid_before": record.not_valid_before.isoformat(),
            "not_valid_after": record.not_valid_after.isoformat(),
            "fingerprint_sha256": record.fingerprint_sha256,
            "environment": record.environment,
            "created_at": created_at.isoformat(),
            "has_password": record.has_password,
        }
        created_directory = not entry.exists()
        # Kopia poprzedniego wpisu: `save(overwrite=True)` zastępuje trzy pliki
        # po kolei, więc błąd zapisu w środku zostawiłby nowy certyfikat ze starym
        # kluczem (albo odwrotnie) i bezpowrotnie zgubił poprzednią parę.
        backups: dict[str, bytes] = {}
        for file_name in (_CERT_FILE, _KEY_FILE, _META_FILE):
            existing = entry / file_name
            if existing.is_file():
                backups[file_name] = existing.read_bytes()
        try:
            self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            entry.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._write_file(entry / _CERT_FILE, certificate_pem)
            self._write_file(entry / _KEY_FILE, private_key_pem)
            self._write_file(
                entry / _META_FILE,
                json.dumps(meta, ensure_ascii=True, indent=2).encode("utf-8"),
            )
        except OSError as exc:
            if created_directory:
                with suppress(OSError):
                    for child in entry.iterdir():
                        child.unlink(missing_ok=True)
                    entry.rmdir()
            else:
                for file_name, data in backups.items():
                    with suppress(OSError):
                        self._write_file(entry / file_name, data)
            raise CertificateStoreError(
                f"Nie można zapisać certyfikatu '{normalized}' w {entry}: {exc}."
            ) from exc
        return record

    def _record_for(
        self,
        name: str,
        entry: Path,
        certificate: x509.Certificate,
    ) -> CertificateRecord:
        meta = self._read_meta(entry)
        environment = meta.get("environment")
        created_at: datetime | None = None
        raw_created = meta.get("created_at")
        if isinstance(raw_created, str):
            with suppress(ValueError):
                created_at = datetime.fromisoformat(raw_created)
        has_password = meta.get("has_password") is True
        return _record(
            name,
            certificate,
            environment=environment if isinstance(environment, str) else None,
            created_at=created_at,
            has_password=has_password,
        )

    def load(self, name: str, *, password: str | bytes | None = None) -> StoredCertificate:
        """Odczytuje certyfikat i klucz.

        Args:
            name: Nazwa wpisu.
            password: Hasło klucza, jeśli był szyfrowany przy zapisie.

        Returns:
            Certyfikat, klucz i metadane.

        Raises:
            CertificateStoreError: Gdy wpis nie istnieje, pliki są uszkodzone,
                hasło jest błędne albo klucz nie pasuje do certyfikatu.
        """
        normalized = _validate_name(name)
        entry = self._entry_dir(normalized)
        self._reject_symlink(normalized, entry)
        if not entry.is_dir():
            raise CertificateStoreError(f"Certyfikat '{normalized}' nie istnieje.")
        certificate_path = entry / _CERT_FILE
        key_path = entry / _KEY_FILE
        try:
            certificate_pem = certificate_path.read_bytes()
            private_key_pem = key_path.read_bytes()
        except OSError as exc:
            raise CertificateStoreError(
                f"Certyfikat '{normalized}' jest niekompletny (brak cert.pem lub key.pem): {exc}."
            ) from exc
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem)
        except ValueError as exc:
            raise CertificateStoreError(
                f"Certyfikat '{normalized}' ma niepoprawny plik cert.pem: {exc}."
            ) from exc
        password_bytes = _password_bytes(password)
        try:
            private_key = load_pem_private_key(private_key_pem, password=password_bytes)
        except TypeError as exc:
            raise CertificateStoreError(
                f"Klucz certyfikatu '{normalized}' jest zaszyfrowany — podaj hasło."
            ) from exc
        except ValueError as exc:
            raise CertificateStoreError(
                f"Nie można odszyfrować klucza certyfikatu '{normalized}': {exc}."
            ) from exc
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise CertificateStoreError(
                f"Nieobsługiwany typ klucza w '{normalized}': {type(private_key).__name__}."
            )
        _ensure_pair(certificate, private_key)
        record = self._record_for(normalized, entry, certificate)
        return StoredCertificate(
            record=record,
            certificate=certificate,
            private_key=private_key,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
        )

    def list(self) -> tuple[CertificateRecord, ...]:
        """Zwraca metadane wszystkich wpisów, posortowane po nazwie.

        Wpisy niekompletne lub uszkodzone są pomijane z ostrzeżeniem
        :class:`RuntimeWarning` — jedno zepsute katalog nie może blokować
        odczytu pozostałych certyfikatów.
        """
        if not self._directory.is_dir():
            return ()
        records: list[CertificateRecord] = []
        for entry in sorted(self._directory.iterdir(), key=lambda path: path.name):
            if not entry.is_dir() or entry.is_symlink():
                continue
            if not _NAME_RE.fullmatch(entry.name) or ".." in entry.name:
                continue
            certificate_path = entry / _CERT_FILE
            if not certificate_path.is_file():
                continue
            if not (entry / _KEY_FILE).is_file():
                # Wpis bez klucza nie jest użytecznym certyfikatem — pokazujemy
                # tylko kompletne pary, ale nie ukrywamy problemu po cichu.
                warnings.warn(
                    f"Pomijam niekompletny certyfikat '{entry.name}': brak key.pem.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            try:
                certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
            except (OSError, ValueError) as exc:
                warnings.warn(
                    f"Pomijam uszkodzony certyfikat '{entry.name}': {exc}.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            records.append(self._record_for(entry.name, entry, certificate))
        return tuple(records)

    def delete(self, name: str) -> None:
        """Usuwa wpis wraz z plikami.

        Raises:
            CertificateStoreError: Gdy wpis nie istnieje.
        """
        normalized = _validate_name(name)
        entry = self._entry_dir(normalized)
        self._reject_symlink(normalized, entry)
        if not entry.is_dir():
            raise CertificateStoreError(f"Certyfikat '{normalized}' nie istnieje.")
        children = list(entry.iterdir())
        # Najpierw sprawdzenie, potem usuwanie: wcześniej pliki ginęły, a
        # `rmdir` wywalał się na podkatalogu, zostawiając wpis w połowie
        # usunięty.
        if any(child.is_dir() for child in children):
            raise CertificateStoreError(
                f"Nie można usunąć certyfikatu '{normalized}': katalog wpisu "
                "zawiera podkatalogi."
            )
        try:
            for child in children:
                child.unlink(missing_ok=True)
            entry.rmdir()
        except OSError as exc:
            raise CertificateStoreError(
                f"Nie można usunąć certyfikatu '{normalized}': {exc}."
            ) from exc

    def exists(self, name: str) -> bool:
        """Czy wpis o podanej nazwie istnieje (symlink nie liczy się jako wpis)."""
        normalized = _validate_name(name)
        entry = self._entry_dir(normalized)
        return entry.is_dir() and not entry.is_symlink()

    def _read_certificate(self, name: str, entry: Path) -> x509.Certificate:
        try:
            data = (entry / _CERT_FILE).read_bytes()
        except OSError as exc:
            raise CertificateStoreError(
                f"Certyfikat '{name}' jest niekompletny (brak cert.pem): {exc}."
            ) from exc
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError as exc:
            raise CertificateStoreError(
                f"Certyfikat '{name}' ma niepoprawny plik cert.pem: {exc}."
            ) from exc

    def record(self, name: str) -> CertificateRecord:
        """Metadane wpisu — bez wczytywania i odszyfrowywania klucza."""
        normalized = _validate_name(name)
        entry = self._entry_dir(normalized)
        self._reject_symlink(normalized, entry)
        if not entry.is_dir():
            raise CertificateStoreError(f"Certyfikat '{normalized}' nie istnieje.")
        return self._record_for(normalized, entry, self._read_certificate(normalized, entry))


__all__ = [
    "CertificateRecord",
    "CertificateStore",
    "CertificateStoreError",
    "FileCertificateStore",
    "PrivateKey",
    "StoredCertificate",
]
