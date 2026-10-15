from __future__ import annotations

import json
import os
import re
import uuid
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ksef_client.services.sessions import BatchSessionState, OnlineSessionState

from .config.paths import cache_dir
from .errors import CliError
from .exit_codes import ExitCode

_CHECKPOINT_SCHEMA_VERSION = 1
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_session_id(session_id: str) -> str:
    normalized = session_id.strip()
    if not _SESSION_ID_RE.fullmatch(normalized):
        raise CliError(
            "Invalid session id.",
            ExitCode.VALIDATION_ERROR,
            "Use 1-128 characters from: letters, digits, dot, dash, underscore.",
        )
    return normalized


def _checkpoint_root() -> Path:
    return cache_dir() / "sessions"


def _profile_dir(profile: str) -> Path:
    return _checkpoint_root() / profile


def _checkpoint_path(profile: str, session_id: str) -> Path:
    safe_id = _validate_session_id(session_id)
    return _profile_dir(profile) / f"{safe_id}.json"


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # `mkdir` poza `try` uciekał jako surowy OSError, więc CLI kończyło się
        # nieoczekiwanym kodem wyjścia (UNEXPECTED/6) zamiast CONFIG_ERROR.
        raise CliError(
            "Cannot create the checkpoint directory.",
            ExitCode.CONFIG_ERROR,
            "Grant write access to the cache directory or update its location settings.",
        ) from exc
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    data = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)
    try:
        # Plik tymczasowy powstaje z prawami 0600 JUŻ przy tworzeniu: checkpoint
        # niesie klucz sesji, a `open("w")` dawał 0644 (przy typowym umask 022)
        # i `chmod` następował dopiero po `os.replace` — przerwanie procesu
        # w tym oknie zostawiało czytelny dla wszystkich plik z kluczem.
        descriptor = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            with suppress(OSError):
                os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except OSError as exc:
        with suppress(OSError):
            tmp_path.unlink()
        raise CliError(
            "Cannot persist session checkpoint.",
            ExitCode.CONFIG_ERROR,
            "Grant write access to CLI cache directory.",
        ) from exc
    if os.name != "nt":
        with suppress(OSError):
            os.chmod(path, 0o600)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(
            f"Cannot read session checkpoint: {path}",
            ExitCode.CONFIG_ERROR,
            "The checkpoint file is missing or invalid JSON.",
        ) from exc
    if not isinstance(raw, dict):
        raise CliError(
            f"Invalid session checkpoint payload: {path}",
            ExitCode.CONFIG_ERROR,
            "The checkpoint file must contain a JSON object.",
        )
    return raw


def _optional_string(value: Any, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Invalid {field_name}: expected string or null.")
    return value


def _required_string(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"Invalid {field_name}: expected non-empty string.")
    return value


def _required_int(value: Any, *, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"Invalid {field_name}: expected non-negative integer.")
    return value


def _required_string_list(value: Any, *, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"Invalid {field_name}: expected JSON array.")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"Invalid {field_name}: expected array of strings.")
        result.append(item)
    return result


def _required_int_list(value: Any, *, field_name: str) -> list[int]:
    if not isinstance(value, list):
        raise ValueError(f"Invalid {field_name}: expected JSON array.")
    result: list[int] = []
    for item in value:
        if not isinstance(item, int) or item < 0:
            raise ValueError(f"Invalid {field_name}: expected array of non-negative integers.")
        result.append(item)
    return result


@dataclass(frozen=True)
class BatchPayloadSource:
    kind: str
    path: str
    source_sha256_base64: str
    source_size: int

    def __post_init__(self) -> None:
        if self.kind not in {"zip", "tar_gz", "directory", "tar_gz_directory"}:
            raise ValueError(f"Invalid payload source kind: {self.kind!r}.")
        if self.path.strip() == "":
            raise ValueError("Invalid payload source path: expected non-empty string.")
        if self.source_size < 0:
            raise ValueError("Invalid source_size: expected non-negative integer.")
        if self.source_sha256_base64.strip() == "":
            raise ValueError("Invalid source_sha256_base64: expected non-empty string.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "source_sha256_base64": self.source_sha256_base64,
            "source_size": self.source_size,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> BatchPayloadSource:
        return cls(
            kind=_required_string(payload.get("kind"), field_name="payload_source.kind"),
            path=_required_string(payload.get("path"), field_name="payload_source.path"),
            source_sha256_base64=_required_string(
                payload.get("source_sha256_base64"),
                field_name="payload_source.source_sha256_base64",
            ),
            source_size=_required_int(
                payload.get("source_size"),
                field_name="payload_source.source_size",
            ),
        )


@dataclass(frozen=True)
class OnlineSessionCheckpoint:
    id: str
    profile: str
    base_url: str
    stage: str
    session_state: OnlineSessionState
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    last_invoice_ref: str | None = None
    sent_invoice_refs: list[str] = field(default_factory=list)
    schema_version: int = _CHECKPOINT_SCHEMA_VERSION
    kind: str = "online"

    def __post_init__(self) -> None:
        _ = _validate_session_id(self.id)
        if self.schema_version != _CHECKPOINT_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported checkpoint schema_version: {self.schema_version!r}."
            )
        if self.kind != "online":
            raise ValueError(f"Invalid checkpoint kind: {self.kind!r}.")
        if self.profile.strip() == "":
            raise ValueError("Invalid profile: expected non-empty string.")
        if self.base_url.strip() == "":
            raise ValueError("Invalid base_url: expected non-empty string.")
        if self.stage.strip() == "":
            raise ValueError("Invalid stage: expected non-empty string.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "profile": self.profile,
            "base_url": self.base_url,
            "kind": self.kind,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "stage": self.stage,
            "session_state": self.session_state.to_dict(),
            "last_invoice_ref": self.last_invoice_ref,
            "sent_invoice_refs": list(self.sent_invoice_refs),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> OnlineSessionCheckpoint:
        if payload.get("schema_version") != _CHECKPOINT_SCHEMA_VERSION:
            raise ValueError(
                "Unsupported checkpoint schema_version: "
                f"{payload.get('schema_version')!r}."
            )
        if payload.get("kind") != "online":
            raise ValueError(f"Invalid checkpoint kind: {payload.get('kind')!r}.")
        session_payload = payload.get("session_state")
        if not isinstance(session_payload, dict):
            raise ValueError("Invalid session_state: expected JSON object.")
        return cls(
            id=_required_string(payload.get("id"), field_name="id"),
            profile=_required_string(payload.get("profile"), field_name="profile"),
            base_url=_required_string(payload.get("base_url"), field_name="base_url"),
            kind="online",
            created_at=_required_string(payload.get("created_at"), field_name="created_at"),
            updated_at=_required_string(payload.get("updated_at"), field_name="updated_at"),
            stage=_required_string(payload.get("stage"), field_name="stage"),
            session_state=OnlineSessionState.from_dict(session_payload),
            last_invoice_ref=_optional_string(
                payload.get("last_invoice_ref"),
                field_name="last_invoice_ref",
            ),
            sent_invoice_refs=_required_string_list(
                payload.get("sent_invoice_refs", []),
                field_name="sent_invoice_refs",
            ),
        )


@dataclass(frozen=True)
class BatchSessionCheckpoint:
    id: str
    profile: str
    base_url: str
    stage: str
    session_state: BatchSessionState
    payload_source: BatchPayloadSource
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    uploaded_ordinals: list[int] = field(default_factory=list)
    last_upo_ref: str | None = None
    schema_version: int = _CHECKPOINT_SCHEMA_VERSION
    kind: str = "batch"

    def __post_init__(self) -> None:
        _ = _validate_session_id(self.id)
        if self.schema_version != _CHECKPOINT_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported checkpoint schema_version: {self.schema_version!r}."
            )
        if self.kind != "batch":
            raise ValueError(f"Invalid checkpoint kind: {self.kind!r}.")
        if self.profile.strip() == "":
            raise ValueError("Invalid profile: expected non-empty string.")
        if self.base_url.strip() == "":
            raise ValueError("Invalid base_url: expected non-empty string.")
        if self.stage.strip() == "":
            raise ValueError("Invalid stage: expected non-empty string.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "profile": self.profile,
            "base_url": self.base_url,
            "kind": self.kind,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "stage": self.stage,
            "session_state": self.session_state.to_dict(),
            "payload_source": self.payload_source.to_dict(),
            "uploaded_ordinals": list(self.uploaded_ordinals),
            "last_upo_ref": self.last_upo_ref,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> BatchSessionCheckpoint:
        if payload.get("schema_version") != _CHECKPOINT_SCHEMA_VERSION:
            raise ValueError(
                "Unsupported checkpoint schema_version: "
                f"{payload.get('schema_version')!r}."
            )
        if payload.get("kind") != "batch":
            raise ValueError(f"Invalid checkpoint kind: {payload.get('kind')!r}.")
        session_payload = payload.get("session_state")
        if not isinstance(session_payload, dict):
            raise ValueError("Invalid session_state: expected JSON object.")
        source_payload = payload.get("payload_source")
        if not isinstance(source_payload, dict):
            raise ValueError("Invalid payload_source: expected JSON object.")
        return cls(
            id=_required_string(payload.get("id"), field_name="id"),
            profile=_required_string(payload.get("profile"), field_name="profile"),
            base_url=_required_string(payload.get("base_url"), field_name="base_url"),
            kind="batch",
            created_at=_required_string(payload.get("created_at"), field_name="created_at"),
            updated_at=_required_string(payload.get("updated_at"), field_name="updated_at"),
            stage=_required_string(payload.get("stage"), field_name="stage"),
            session_state=BatchSessionState.from_dict(session_payload),
            payload_source=BatchPayloadSource.from_dict(source_payload),
            uploaded_ordinals=_required_int_list(
                payload.get("uploaded_ordinals", []),
                field_name="uploaded_ordinals",
            ),
            last_upo_ref=_optional_string(payload.get("last_upo_ref"), field_name="last_upo_ref"),
        )


SessionCheckpoint = OnlineSessionCheckpoint | BatchSessionCheckpoint


def checkpoint_from_dict(payload: dict[str, Any]) -> SessionCheckpoint:
    kind = payload.get("kind")
    try:
        if kind == "online":
            return OnlineSessionCheckpoint.from_dict(payload)
        if kind == "batch":
            return BatchSessionCheckpoint.from_dict(payload)
    except ValueError as exc:
        raise CliError(
            "Invalid session checkpoint payload.",
            ExitCode.CONFIG_ERROR,
            str(exc),
        ) from exc
    raise CliError(
        "Invalid session checkpoint payload.",
        ExitCode.CONFIG_ERROR,
        f"Unsupported checkpoint kind: {kind!r}.",
    )


def save_checkpoint(checkpoint: SessionCheckpoint, *, overwrite: bool = True) -> Path:
    path = _checkpoint_path(checkpoint.profile, checkpoint.id)
    if path.exists() and not overwrite:
        raise CliError(
            f"Session checkpoint '{checkpoint.id}' already exists.",
            ExitCode.VALIDATION_ERROR,
            "Choose a different --id or overwrite the existing checkpoint.",
        )
    _write_json_atomic(path, checkpoint.to_dict())
    return path


def load_checkpoint(profile: str, session_id: str) -> SessionCheckpoint:
    path = _checkpoint_path(profile, session_id)
    if not path.exists():
        raise CliError(
            f"Session checkpoint '{session_id}' does not exist.",
            ExitCode.CONFIG_ERROR,
            "Create it first with `ksef session ... open` or `ksef send ... --save-session`.",
        )
    return checkpoint_from_dict(_read_json(path))


def list_checkpoints(profile: str, *, include_broken: bool = False) -> list[SessionCheckpoint]:
    """Checkpointy profilu; uszkodzone pliki nie znikają bez śladu.

    `include_broken=True` zgłasza błąd zamiast pomijać plik — `session list`
    pokazuje wtedy, że w katalogu leży coś, czego nie da się odczytać (wcześniej
    lista wyglądała na kompletną, choć część plików była pomijana).
    """
    directory = _profile_dir(profile)
    if not directory.exists():
        return []
    checkpoints: list[SessionCheckpoint] = []
    for path in sorted(directory.glob("*.json")):
        try:
            checkpoints.append(checkpoint_from_dict(_read_json(path)))
        except CliError as exc:
            if include_broken:
                raise CliError(
                    f"Cannot read session checkpoint '{path.name}': {exc.message}",
                    ExitCode.CONFIG_ERROR,
                    "Remove or fix the file, then run the command again.",
                ) from exc
            continue
    return checkpoints


def list_unreadable_checkpoints(profile: str) -> list[str]:
    """Nazwy plików checkpointów, których nie da się odczytać (do ostrzeżenia)."""
    directory = _profile_dir(profile)
    if not directory.exists():
        return []
    broken: list[str] = []
    for path in sorted(directory.glob("*.json")):
        try:
            checkpoint_from_dict(_read_json(path))
        except CliError:
            broken.append(path.name)
    return broken


def delete_all_checkpoints(profile: str) -> int:
    """Usuwa wszystkie checkpointy profilu i zwraca liczbę usuniętych plików.

    Używane przez `profile delete`: bez tego nowy profil o tej samej nazwie
    dziedziczył sesje poprzednika (wraz z kluczem i IV sesji w checkpoincie).
    """
    directory = _profile_dir(profile)
    if not directory.exists():
        return 0
    removed = 0
    for path in sorted(directory.glob("*.json")):
        try:
            path.unlink()
            removed += 1
        except OSError as exc:
            raise CliError(
                "Cannot delete session checkpoint.",
                ExitCode.CONFIG_ERROR,
                "Check filesystem permissions and try again.",
            ) from exc
    with suppress(OSError):
        directory.rmdir()
    return removed


def delete_checkpoint(profile: str, session_id: str) -> None:
    path = _checkpoint_path(profile, session_id)
    if not path.exists():
        raise CliError(
            f"Session checkpoint '{session_id}' does not exist.",
            ExitCode.CONFIG_ERROR,
            "Nothing to delete.",
        )
    try:
        path.unlink()
    except OSError as exc:
        raise CliError(
            "Cannot delete session checkpoint.",
            ExitCode.CONFIG_ERROR,
            "Check filesystem permissions and try again.",
        ) from exc


def update_checkpoint(
    checkpoint: SessionCheckpoint,
    **changes: Any,
) -> SessionCheckpoint:
    updated = replace(checkpoint, **changes, updated_at=_now_iso())
    save_checkpoint(updated, overwrite=True)
    return updated


def export_checkpoint(
    profile: str, session_id: str, out_path: Path, *, overwrite: bool = False
) -> Path:
    """Zapisuje checkpoint do pliku; bez `overwrite` nie nadpisuje istniejącego.

    Checkpoint zawiera klucz i IV sesji, więc ciche nadpisanie cudzego pliku
    (np. `--out` wskazujące na istniejący dokument) niszczyło dane bez ostrzeżenia.
    """
    checkpoint = load_checkpoint(profile, session_id)
    target = out_path
    if target.exists() and target.is_dir():
        target = target / f"session-{checkpoint.id}.json"
    if str(out_path).replace("\\", "/").endswith("/"):
        target = Path(str(out_path).replace("\\", "/")) / f"session-{checkpoint.id}.json"
    if target.exists() and not overwrite:
        raise CliError(
            f"File already exists: {target}",
            ExitCode.IO_ERROR,
            "Pass --overwrite to replace it.",
        )
    _write_json_atomic(target, checkpoint.to_dict())
    return target


def _normalize_base_url(value: str) -> str:
    """Adres do porównania: bez ukośnika na końcu, bez portu domyślnego, małymi literami.

    `https://host:443` i `https://host` to ten sam adres — bez zdjęcia portu
    domyślnego legalny checkpoint bywał fałszywie odrzucany.
    """
    normalized = value.strip().rstrip("/").lower()
    for scheme, default_port in (("https://", ":443"), ("http://", ":80")):
        if normalized.startswith(scheme) and normalized.endswith(default_port):
            return normalized[: -len(default_port)]
    return normalized


def require_matching_base_url(checkpoint: SessionCheckpoint, expected_base_url: str) -> None:
    """Sprawdza, że checkpoint nie wskazuje innego adresu niż efektywny adres komendy.

    Checkpoint bywa plikiem z zewnątrz (`session import`), a jego `base_url`
    decyduje, DOKĄD trafia token dostępowy profilu (`session online send`,
    `close`, `status`). Wcześniej porównywana była wyłącznie nazwa profilu, więc
    spreparowany plik mógł wysłać token KSeF i treść faktury na dowolny host.
    """
    if _normalize_base_url(checkpoint.base_url) == _normalize_base_url(expected_base_url):
        return
    raise CliError(
        "Checkpoint base_url does not match the effective base URL.",
        ExitCode.VALIDATION_ERROR,
        f"Checkpoint points at '{checkpoint.base_url}', this command uses "
        f"'{expected_base_url}'. Re-import the checkpoint from the matching environment, "
        "select that profile or pass the matching --base-url.",
    )


def _known_ksef_hosts() -> set[str]:
    """Hosty środowisk KSeF — do rozpoznania checkpointu z zewnątrz."""
    from ksef_client.config import KsefEnvironment

    hosts = set()
    for environment in KsefEnvironment:
        host = urlparse(environment.value).hostname
        if host:
            hosts.add(host.lower())
    return hosts


def require_known_ksef_host(base_url: str, *, allow_foreign_host: bool = False) -> None:
    """Importowany checkpoint musi wskazywać znane środowisko KSeF.

    Plik checkpointu jest danymi z zewnątrz, a jego `base_url` decyduje, dokąd
    trafi token dostępowy profilu. Dopuszczenie dowolnego hosta oznaczało, że
    wystarczyło podać zgodny `--base-url`, żeby „zalegalizować” obcy adres —
    teraz nieznany host wymaga świadomej zgody (`--allow-foreign-host`), co jest
    potrzebne tylko przy własnych wdrożeniach.
    """
    if allow_foreign_host:
        return
    host = (urlparse(base_url).hostname or "").lower()
    known = _known_ksef_hosts()
    if host in known:
        return
    raise CliError(
        f"Checkpoint points at an unknown host: {host or base_url!r}.",
        ExitCode.VALIDATION_ERROR,
        f"Known KSeF hosts: {', '.join(sorted(known))}. "
        "Pass --allow-foreign-host if you really use a custom deployment.",
    )


def import_checkpoint(
    profile: str,
    source_path: Path,
    *,
    session_id: str | None = None,
    expected_base_url: str | None = None,
    allow_foreign_host: bool = False,
) -> SessionCheckpoint:
    if not source_path.exists() or not source_path.is_file():
        raise CliError(
            f"Checkpoint file does not exist: {source_path}",
            ExitCode.IO_ERROR,
            "Use --in with an existing JSON checkpoint file.",
        )
    checkpoint = checkpoint_from_dict(_read_json(source_path))
    if checkpoint.profile != profile:
        raise CliError(
            "Checkpoint profile does not match selected profile.",
            ExitCode.VALIDATION_ERROR,
            f"Checkpoint profile is '{checkpoint.profile}', selected profile is '{profile}'.",
        )
    require_known_ksef_host(checkpoint.base_url, allow_foreign_host=allow_foreign_host)
    if expected_base_url is not None:
        require_matching_base_url(checkpoint, expected_base_url)
    if session_id is not None:
        checkpoint = replace(checkpoint, id=_validate_session_id(session_id))
    save_checkpoint(checkpoint, overwrite=True)
    return checkpoint


__all__ = [
    "BatchPayloadSource",
    "OnlineSessionCheckpoint",
    "BatchSessionCheckpoint",
    "SessionCheckpoint",
    "checkpoint_from_dict",
    "save_checkpoint",
    "load_checkpoint",
    "list_checkpoints",
    "delete_checkpoint",
    "update_checkpoint",
    "export_checkpoint",
    "import_checkpoint",
    "delete_all_checkpoints",
    "list_unreadable_checkpoints",
    "require_matching_base_url",
]
