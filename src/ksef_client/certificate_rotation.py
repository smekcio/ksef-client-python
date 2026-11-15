"""Verify a named XAdES credential before selecting it for a worker profile."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .certificates import (
    CertificateRecord,
    CertificateStoreError,
    FileCertificateStore,
    StoredCertificate,
    _validate_name,
)
from .exceptions import KsefError
from .facade import Ksef, XadesCredentials, connection_options
from .invoice_xml_storage import _safe_directory
from .operations import environment_key
from .profiles import Profile
from .request_control import request_control

_logger = logging.getLogger(__name__)
_SUBJECT_IDENTIFIER_TYPES = {"certificateSubject", "certificateFingerprint"}


class CertificateRotationError(CertificateStoreError):
    """The profile's XAdES credential could not be safely selected."""


@dataclass(frozen=True)
class CertificateSelection:
    """Active immutable credential version and optimistic-lock generation."""

    name: str
    fingerprint_sha256: str
    generation: int
    subject_identifier_type: str
    verify_certificate_chain: bool | None = None
    enforce_xades_compliance: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not isinstance(self.fingerprint_sha256, str)
            or re.fullmatch("[0-9a-f]{64}", self.fingerprint_sha256) is None
            or type(self.generation) is not int
            or self.generation < 1
            or self.subject_identifier_type not in _SUBJECT_IDENTIFIER_TYPES
        ):
            raise CertificateRotationError("Invalid stored certificate selection")
        try:
            if _validate_name(self.name) != self.name:
                raise CertificateStoreError("Noncanonical name")
        except CertificateStoreError:
            raise CertificateRotationError("Invalid stored certificate name") from None


@dataclass(frozen=True)
class CertificateHealth:
    """Local X.509 validity for the currently selected credential."""

    selection: CertificateSelection | None
    status: str
    not_valid_before: datetime | None = None
    not_valid_after: datetime | None = None


class ProfileCertificates:
    """Share a verified certificate selector between workers on the same machine.

    Store each certificate/key pair under a new name. Keep the previous entry
    until workers using its auth session finish, then retire it separately.
    """

    def __init__(
        self,
        path: str | Path,
        profile: Profile,
        *,
        store: FileCertificateStore | None = None,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
    ) -> None:
        self._path = Path(path).absolute()
        self._profile = profile
        if verify_certificate_chain is not None and type(verify_certificate_chain) is not bool:
            raise TypeError("verify_certificate_chain must be bool or None")
        if type(enforce_xades_compliance) is not bool:
            raise TypeError("enforce_xades_compliance must be bool")
        self._verify_certificate_chain = verify_certificate_chain
        self._enforce_xades_compliance = enforce_xades_compliance
        self._store = store if store is not None else FileCertificateStore.default()
        options, kind, context = connection_options(profile=profile)
        endpoint = urlsplit(options.normalized_base_url())
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.query
            or endpoint.fragment
        ):
            raise CertificateRotationError("XAdES rotation requires a fixed HTTPS profile endpoint")
        identity_parts = [
            profile.name,
            environment_key(options.normalized_base_url()),
            kind,
            context,
        ]
        self._scope = self._scope_hash(identity_parts)
        self._legacy_policies = {
            self._scope_hash([*identity_parts, chain, compliance]): (chain, compliance)
            for chain in (None, False, True)
            for compliance in (False, True)
            if chain is not None or compliance
        }
        self._legacy_policies[self._scope] = (None, False)
        self._legacy_matcher = ",".join("?" for _ in self._legacy_policies)

    @staticmethod
    def _scope_hash(parts: Sequence[str | bool | None]) -> str:
        return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()

    def _policy_matches(self, selection: CertificateSelection) -> bool:
        return (
            selection.verify_certificate_chain == self._verify_certificate_chain
            and selection.enforce_xades_compliance == self._enforce_xades_compliance
        )

    def _open(self) -> sqlite3.Connection:
        _safe_directory(self._path.parent, allow_missing=True)
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _safe_directory(self._path.parent)
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = self._path.with_name(self._path.name + suffix)
            if path.is_symlink() or (
                path.exists()
                and (
                    not path.is_file()
                    or path.stat().st_nlink != 1
                    or getattr(path.lstat(), "st_file_attributes", 0) & 1024
                )
            ):
                raise CertificateRotationError("Unsafe certificate selector path")
        try:
            fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        connection = sqlite3.connect(self._path)
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS certificate_selection_v2 ("
                "scope TEXT PRIMARY KEY, name TEXT NOT NULL, fingerprint TEXT NOT NULL, "
                "generation INTEGER NOT NULL CHECK(generation > 0), "
                "subject_identifier_type TEXT NOT NULL, "
                "verify_certificate_chain INTEGER CHECK(verify_certificate_chain IN (0, 1)), "
                "enforce_xades_compliance INTEGER NOT NULL "
                "CHECK(enforce_xades_compliance IN (0, 1)))"
            )
        except BaseException:
            connection.close()
            raise
        return connection

    @staticmethod
    def _has_legacy_table(connection: sqlite3.Connection) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'certificate_selection'"
            ).fetchone()
            is not None
        )

    def _selection_state(
        self, connection: sqlite3.Connection
    ) -> tuple[CertificateSelection | None, bool]:
        """Read the current selection or a unique entry from the pre-release schema."""
        row = connection.execute(
            "SELECT name, fingerprint, generation, subject_identifier_type, "
            "verify_certificate_chain, enforce_xades_compliance "
            "FROM certificate_selection_v2 WHERE scope = ?",
            (self._scope,),
        ).fetchone()
        if row is not None:
            name, fingerprint, generation, subject, chain, compliance = row
            return CertificateSelection(
                name,
                fingerprint,
                generation,
                subject,
                None if chain is None else bool(chain),
                bool(compliance),
            ), False
        if not self._has_legacy_table(connection):
            return None, False
        matches = connection.execute(
            "SELECT scope, name, fingerprint, generation, subject_identifier_type "
            f"FROM certificate_selection WHERE scope IN ({self._legacy_matcher})",
            tuple(self._legacy_policies),
        ).fetchall()
        if len(matches) != 1:
            return None, len(matches) > 1
        scope, name, fingerprint, generation, subject = matches[0]
        return CertificateSelection(
            name, fingerprint, generation, subject, *self._legacy_policies[scope]
        ), False

    def status(self, *, warn_before: timedelta = timedelta(days=30)) -> CertificateHealth:
        """Inspect validity and fingerprint without loading/decrypting the key."""
        if warn_before < timedelta(0):
            raise ValueError("warn_before must be non-negative")
        with closing(self._open()) as connection:
            selected, conflict = self._selection_state(connection)
        if conflict:
            return CertificateHealth(None, "reactivation_required")
        if selected is None:
            return CertificateHealth(None, "unconfigured")
        if not self._policy_matches(selected):
            return CertificateHealth(selected, "policy_mismatch")
        try:
            record = self._store.record(selected.name, require_key=True)
        except CertificateStoreError:
            return CertificateHealth(selected, "unavailable")
        if record.fingerprint_sha256 != selected.fingerprint_sha256:
            status = "fingerprint_mismatch"
        else:
            now = datetime.now(timezone.utc)
            status = self._validity(record, now)
            if status == "valid" and record.not_valid_after - now <= warn_before:
                status = "expiring"
        return CertificateHealth(selected, status, record.not_valid_before, record.not_valid_after)

    @staticmethod
    def _validity(record: CertificateRecord, now: datetime) -> str:
        if record.not_valid_before > now:
            return "not_yet_valid"
        if record.not_valid_after <= now:
            return "expired"
        return "valid"

    def _checked_certificate(
        self,
        name: str,
        password: str | bytes | None,
        fingerprint: str | None = None,
    ) -> StoredCertificate:
        if self._store.require_password and password is None:
            raise CertificateRotationError("This certificate store requires a key password")
        stored = self._store.load(name, password=password, require_regular_files=True)
        record = stored.record
        if fingerprint is not None and record.fingerprint_sha256 != fingerprint:
            raise CertificateRotationError("Selected certificate fingerprint changed")
        status = self._validity(record, datetime.now(timezone.utc))
        if status != "valid":
            raise CertificateRotationError(f"Certificate is {status}")
        environment = self._profile.environment
        if record.environment and (environment is None or record.environment != environment.name):
            raise CertificateRotationError("Certificate environment does not match the profile")
        return stored

    @staticmethod
    def _revoke_session(client: Ksef) -> None:
        try:
            client.api.auth.revoke_current_session()
        except KsefError:
            _logger.warning("Could not revoke the temporary XAdES session")

    def activate(
        self,
        name: str,
        *,
        expected_generation: int,
        subject_identifier_type: str = "certificateSubject",
        verify: Callable[[Ksef], None] | None = None,
        password: str | bytes | None = None,
        timeout: float = 120,
    ) -> CertificateSelection:
        """Verify the candidate with KSeF, then atomically compare and replace the selection."""
        if type(expected_generation) is not int or expected_generation < 0:
            raise ValueError("expected_generation must be a non-negative integer")
        with closing(self._open()) as connection:
            current, _ = self._selection_state(connection)
        if (current.generation if current else 0) != expected_generation:
            raise CertificateRotationError("Certificate selection changed")
        if subject_identifier_type not in _SUBJECT_IDENTIFIER_TYPES:
            raise ValueError("Invalid XAdES subject identifier type")
        candidate = self._checked_certificate(name, password)
        record = candidate.record
        credentials = XadesCredentials.from_stored_certificate(
            candidate,
            subject_identifier_type=subject_identifier_type,
            verify_certificate_chain=self._verify_certificate_chain,
            enforce_xades_compliance=self._enforce_xades_compliance,
        )
        with Ksef.connect(
            credentials=credentials, profile=self._profile, timeout=timeout
        ) as client:
            try:
                if verify is not None:
                    with request_control(timeout_seconds=timeout) as control:
                        verify(client)
                        control.check()
            finally:
                self._revoke_session(client)
        # Verify that the same usable pair is still available after the remote
        # check, which may take longer than a concurrent store update.
        self._checked_certificate(name, password, record.fingerprint_sha256)
        with closing(self._open()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current, _ = self._selection_state(connection)
            if (current.generation if current else 0) != expected_generation:
                raise CertificateRotationError("Certificate selection changed")
            selected = CertificateSelection(
                record.name,
                record.fingerprint_sha256,
                expected_generation + 1,
                subject_identifier_type,
                self._verify_certificate_chain,
                self._enforce_xades_compliance,
            )
            connection.execute(
                "INSERT INTO certificate_selection_v2 VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(scope) DO UPDATE SET name = excluded.name, "
                "fingerprint = excluded.fingerprint, generation = excluded.generation, "
                "subject_identifier_type = excluded.subject_identifier_type, "
                "verify_certificate_chain = excluded.verify_certificate_chain, "
                "enforce_xades_compliance = excluded.enforce_xades_compliance",
                (
                    self._scope,
                    selected.name,
                    selected.fingerprint_sha256,
                    selected.generation,
                    selected.subject_identifier_type,
                    selected.verify_certificate_chain,
                    selected.enforce_xades_compliance,
                ),
            )
            if self._has_legacy_table(connection):
                connection.execute(
                    f"DELETE FROM certificate_selection WHERE scope IN ({self._legacy_matcher})",
                    tuple(self._legacy_policies),
                )
        return selected

    def connect(
        self,
        *,
        password: str | bytes | None = None,
        password_for: Callable[[str], str | bytes | None] | None = None,
        timeout: float = 120,
    ) -> Ksef:
        """Start a fresh SDK client with the active credential for this worker cycle."""
        with closing(self._open()) as connection:
            selected, conflict = self._selection_state(connection)
        if conflict:
            raise CertificateRotationError(
                "Multiple legacy selections require explicit reactivation"
            )
        if selected is None:
            raise CertificateRotationError("No active XAdES certificate for this profile")
        if not self._policy_matches(selected):
            raise CertificateRotationError(
                "Worker XAdES policy does not match the active selection"
            )
        if password_for is not None:
            if password is not None:
                raise ValueError("Pass a password or a version-specific password provider")
            password = password_for(selected.name)
        stored = self._checked_certificate(selected.name, password, selected.fingerprint_sha256)
        credentials = XadesCredentials.from_stored_certificate(
            stored,
            subject_identifier_type=selected.subject_identifier_type,
            verify_certificate_chain=self._verify_certificate_chain,
            enforce_xades_compliance=self._enforce_xades_compliance,
        )
        return Ksef.connect(credentials=credentials, profile=self._profile, timeout=timeout)

    @contextmanager
    def session(
        self,
        *,
        password: str | bytes | None = None,
        password_for: Callable[[str], str | bytes | None] | None = None,
        timeout: float = 120,
    ) -> Iterator[Ksef]:
        """Open one worker cycle with the current credential, then revoke its auth session."""
        with self.connect(password=password, password_for=password_for, timeout=timeout) as client:
            try:
                yield client
            finally:
                self._revoke_session(client)
