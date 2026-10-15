from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import PurePosixPath
from typing import IO

#: Maksymalny rozmiar części paczki PRZED zaszyfrowaniem.
#:
#: Kontrakt KSeF opisuje limit dziesiętnie („Maksymalny dozwolony rozmiar części
#: przed zaszyfrowaniem to 100MB"), a oficjalny klient referencyjny używa
#: ``100 * 1000 * 1000``. Wcześniejsza wartość ``100 * 1024 * 1024`` pozwalała
#: wysłać część o 4,86% większą niż dozwolona (100 000 000-104 857 600 B),
#: którą KSeF odrzucał komunikatem „Rozmiar części 1 przekroczył dozwolony
#: rozmiar 100MB".
MAX_BATCH_PART_SIZE_BYTES = 100_000_000
#: Kontrakt: „Maksymalna liczba części to 50" (`BatchFileInfo.fileParts`).
MAX_BATCH_PARTS = 50
#: Maksymalna liczba faktur w paczce eksportu (kontrakt: „Limit liczby faktur: 10 000 sztuk").
EXPORT_MAX_INVOICES = 10_000
#: Limit wpisów archiwum paczki eksportu.
#:
#: Paczka zawiera dodatkowo `_metadata.json`, którego kontrakt **nie wlicza** do
#: limitów algorytmu budowania paczki („Plik z metadanymi(_metadata.json) nie jest
#: wliczany do limitów algorytmu budowania paczki"). Limit `max_files=10_000`
#: odrzucał więc legalną paczkę maksymalną (10 000 faktur + metadane = 10 001 wpisów).
EXPORT_MAX_ARCHIVE_ENTRIES = EXPORT_MAX_INVOICES + 1
_DETERMINISTIC_ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_DETERMINISTIC_TAR_MTIME = 0
#: Porcja odczytu wpisu archiwum.
#:
#: `entry.read()` bez rozmiaru materializował CAŁĄ treść wpisu, więc limity
#: „ochrony przed zip bomb" nie ograniczały pamięci: metadane mogły deklarować
#: 1 KiB, a strumień DEFLATE produkował 128 MiB (peak `tracemalloc` 269 MiB dla
#: archiwum 130 KiB przy limitach 2048/4096/ratio=200). Odczyt porcjami ogranicza
#: pojedyncze wywołanie `decompress()` — dla DEFLATE i ZIP_STORED.
#:
#: Uwaga: `zipfile` woła `decompress()` **bez** `max_length` dla BZIP2 i LZMA
#: (stdlib, `zipfile/__init__.py:1064`), więc dla tych metod pojedyncza porcja
#: danych skompresowanych nadal może rozmnożyć się ponad budżet — sam rozmiar
#: porcji tego nie ogranicza (zmierzone: 32 MiB payloadu = 77 MiB peaku).
_ARCHIVE_READ_CHUNK = 64 * 1024


def build_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in _safe_archive_entries(files, archive_type="zip"):
            info = zipfile.ZipInfo(filename=name, date_time=_DETERMINISTIC_ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0
            zf.writestr(info, content)
    return buffer.getvalue()


def build_tar_gz(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=buffer, mode="wb", mtime=_DETERMINISTIC_TAR_MTIME) as gz,
        tarfile.open(fileobj=gz, mode="w") as tf,
    ):
        for safe_name, content in _safe_archive_entries(files, archive_type="tar.gz"):
            info = tarfile.TarInfo(name=safe_name)
            info.size = len(content)
            info.mtime = _DETERMINISTIC_TAR_MTIME
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tf.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _safe_archive_entries(
    files: dict[str, bytes], *, archive_type: str
) -> list[tuple[str, bytes]]:
    """Nazwy wpisów po sanityzacji, bez kolizji (inaczej wpis ginąłby po cichu).

    ``build_zip`` zapisywał nazwę wywołującego dosłownie (także ``../``), przez co
    własny czytnik SDK odrzucał takie archiwum, a rozpakowujący narażał się na
    path traversal. Dodatkowo dwa różne zapisy (``a//b`` i ``a/b``) normalizują
    się do tej samej nazwy — drugi wpis nadpisałby pierwszy.
    """
    entries: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for raw_name, content in files.items():
        safe_name = _sanitize_archive_entry_name(raw_name, archive_type=archive_type)
        if safe_name in seen:
            raise ValueError(
                f"{archive_type} entry name is duplicated after normalisation: {safe_name}"
            )
        seen.add(safe_name)
        entries.append((safe_name, content))
    return entries


def split_bytes(
    data: bytes,
    max_part_size: int = MAX_BATCH_PART_SIZE_BYTES,
    *,
    max_parts: int = MAX_BATCH_PARTS,
) -> list[bytes]:
    """Dzieli paczkę na części, pilnując kontraktowego limitu liczby części.

    Kontrakt (`BatchFileInfo.fileParts`) mówi: „Maksymalna liczba części to 50.
    Maksymalny dozwolony rozmiar części przed zaszyfrowaniem to 100MB". Wcześniej
    SDK dzielił dane bez tego ograniczenia, więc zbyt duża paczka była wysyłana i
    odrzucana dopiero przez KSeF (błąd 21161) — teraz kończy się czytelnym
    `ValueError` przed wysłaniem.
    """
    if max_part_size <= 0:
        raise ValueError("max_part_size must be positive")
    if max_parts <= 0:
        raise ValueError("max_parts must be positive")
    if len(data) <= max_part_size:
        return [data]
    parts: list[bytes] = []
    for offset in range(0, len(data), max_part_size):
        if len(parts) >= max_parts:
            raise ValueError(
                f"batch package needs more than {max_parts} parts "
                f"(max_part_size={max_part_size}); the KSeF contract allows at most "
                f"{MAX_BATCH_PARTS} parts of {MAX_BATCH_PART_SIZE_BYTES} bytes"
            )
        parts.append(data[offset : offset + max_part_size])
    return parts


def unzip_bytes(
    data: bytes,
    *,
    max_files: int = EXPORT_MAX_ARCHIVE_ENTRIES,
    max_total_uncompressed_size: int = 2_000_000_000,
    max_file_uncompressed_size: int = 500_000_000,
    max_compression_ratio: float | None = 200.0,
) -> dict[str, bytes]:
    return unzip_bytes_safe(
        data,
        max_files=max_files,
        max_total_uncompressed_size=max_total_uncompressed_size,
        max_file_uncompressed_size=max_file_uncompressed_size,
        max_compression_ratio=max_compression_ratio,
    )


def untar_gz_bytes(
    data: bytes,
    *,
    max_files: int = EXPORT_MAX_ARCHIVE_ENTRIES,
    max_total_uncompressed_size: int = 2_000_000_000,
    max_file_uncompressed_size: int = 500_000_000,
    max_compression_ratio: float | None = 200.0,
) -> dict[str, bytes]:
    return untar_gz_bytes_safe(
        data,
        max_files=max_files,
        max_total_uncompressed_size=max_total_uncompressed_size,
        max_file_uncompressed_size=max_file_uncompressed_size,
        max_compression_ratio=max_compression_ratio,
    )


def untar_gz_bytes_safe(
    data: bytes,
    *,
    max_files: int = EXPORT_MAX_ARCHIVE_ENTRIES,
    max_total_uncompressed_size: int = 2_000_000_000,
    max_file_uncompressed_size: int = 500_000_000,
    max_compression_ratio: float | None = 200.0,
) -> dict[str, bytes]:
    _validate_archive_limits(
        max_files=max_files,
        max_total_uncompressed_size=max_total_uncompressed_size,
        max_file_uncompressed_size=max_file_uncompressed_size,
        max_compression_ratio=max_compression_ratio,
    )

    result: dict[str, bytes] = {}
    total_uncompressed = 0
    compressed_size = max(len(data), 1)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf:
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("tar.gz entry must be a regular file")

            if len(result) >= max_files:
                raise ValueError("tar.gz contains too many files")

            # Rozmiar z nagłówka tar jest danymi od atakującego, więc liczymy go
            # tylko jako budżet wstępny — faktycznie odczytane bajty sprawdza
            # `_read_entry_within_budget`.
            declared_size = int(member.size or 0)
            if declared_size > max_file_uncompressed_size:
                raise ValueError("tar.gz contains an entry exceeding max_file_uncompressed_size")

            remaining_total = max_total_uncompressed_size - total_uncompressed
            projected_total = total_uncompressed + declared_size
            if projected_total > max_total_uncompressed_size:
                raise ValueError("tar.gz exceeds max_total_uncompressed_size")
            if (
                max_compression_ratio is not None
                and projected_total / compressed_size > max_compression_ratio
            ):
                raise ValueError("tar.gz exceeds max_compression_ratio")

            safe_name = _sanitize_archive_entry_name(member.name, archive_type="tar.gz")
            if safe_name in result:
                # Dwa wpisy o tej samej nazwie: drugi odczytałby się „po nazwie"
                # i pierwszy zniknąłby bez komunikatu.
                raise ValueError(f"tar.gz contains duplicate entry name: {safe_name}")
            extracted = tf.extractfile(member)
            if extracted is None:
                raise ValueError("tar.gz entry could not be read")
            content = _read_entry_within_budget(
                extracted,
                max_entry_size=max_file_uncompressed_size,
                max_remaining_size=remaining_total,
                entry_limit_message=(
                    "tar.gz contains an entry exceeding max_file_uncompressed_size"
                ),
                total_limit_message="tar.gz exceeds max_total_uncompressed_size",
            )
            total_uncompressed += len(content)
            result[safe_name] = content
    return result


def unzip_bytes_safe(
    data: bytes,
    *,
    max_files: int = EXPORT_MAX_ARCHIVE_ENTRIES,
    max_total_uncompressed_size: int = 2_000_000_000,
    max_file_uncompressed_size: int = 500_000_000,
    max_compression_ratio: float | None = 200.0,
) -> dict[str, bytes]:
    _validate_archive_limits(
        max_files=max_files,
        max_total_uncompressed_size=max_total_uncompressed_size,
        max_file_uncompressed_size=max_file_uncompressed_size,
        max_compression_ratio=max_compression_ratio,
    )

    result: dict[str, bytes] = {}
    total_uncompressed = 0
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        for info in zf.infolist():
            # NIE `info.is_dir()`: na Pythonie 3.10 to `self.filename[-1] == '/'`,
            # więc wpis z pustą nazwą wywracał odczyt `IndexError`-em zamiast
            # naszym `ValueError` (kontrakt mówi o `ValueError`). `endswith` ma
            # identyczną semantykę jak `is_dir()` od 3.11 i nie indeksuje pustego
            # łańcucha, dzięki czemu walidacja nazwy niżej zawsze ma szansę zadziałać.
            if info.filename.endswith("/"):
                continue

            if len(result) >= max_files:
                raise ValueError("zip contains too many files")

            declared_size = int(info.file_size or 0)
            if declared_size > max_file_uncompressed_size:
                raise ValueError("zip contains an entry exceeding max_file_uncompressed_size")

            remaining_total = max_total_uncompressed_size - total_uncompressed
            if declared_size > remaining_total:
                raise ValueError("zip exceeds max_total_uncompressed_size")

            if max_compression_ratio is not None:
                compressed = int(info.compress_size or 0)
                if compressed == 0 and declared_size > 0:
                    raise ValueError("zip entry has suspicious compression metadata")
                if compressed > 0 and declared_size > 0:
                    ratio = declared_size / compressed
                    if ratio > max_compression_ratio:
                        raise ValueError("zip entry exceeds max_compression_ratio")

            safe_name = _sanitize_archive_entry_name(info.filename, archive_type="zip")
            if safe_name in result:
                # `zipfile` rozwiązuje nazwę przez NameToInfo, czyli do OSTATNIEGO
                # wpisu o tej nazwie — wcześniejsze bajty przepadałyby po cichu,
                # a licznik `max_files` liczyłby już zredukowany słownik.
                raise ValueError(f"zip contains duplicate entry name: {safe_name}")
            # Odczyt konkretnego wpisu (nie „po nazwie"), żeby nie zgubić treści,
            # i porcjami — metadane wpisu nie mogą decydować o alokacji pamięci.
            with zf.open(info) as entry:
                content = _read_entry_within_budget(
                    entry,
                    max_entry_size=max_file_uncompressed_size,
                    max_remaining_size=remaining_total,
                    entry_limit_message=(
                        "zip contains an entry exceeding max_file_uncompressed_size"
                    ),
                    total_limit_message="zip exceeds max_total_uncompressed_size",
                )
            total_uncompressed += len(content)
            result[safe_name] = content
    return result


def _read_entry_within_budget(
    stream: IO[bytes],
    *,
    max_entry_size: int,
    max_remaining_size: int,
    entry_limit_message: str,
    total_limit_message: str,
) -> bytes:
    """Czyta wpis porcjami, pilnując budżetu **faktycznie odczytanych** bajtów.

    `file_size` (zip) i `size` (tar) są danymi od atakującego: mogą deklarować
    1 KiB, gdy strumień dekompresji produkuje 128 MiB. Dlatego budżet sprawdzamy
    po każdej porcji, a nie tylko na nagłówku wpisu.
    """
    chunks: list[bytes] = []
    read_bytes = 0
    while True:
        chunk = stream.read(_ARCHIVE_READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        read_bytes += len(chunk)
        if read_bytes > max_entry_size:
            raise ValueError(entry_limit_message)
        if read_bytes > max_remaining_size:
            raise ValueError(total_limit_message)
        chunks.append(chunk)


def _validate_archive_limits(
    *,
    max_files: int,
    max_total_uncompressed_size: int,
    max_file_uncompressed_size: int,
    max_compression_ratio: float | None,
) -> None:
    if max_files <= 0:
        raise ValueError("max_files must be positive")
    if max_total_uncompressed_size <= 0:
        raise ValueError("max_total_uncompressed_size must be positive")
    if max_file_uncompressed_size <= 0:
        raise ValueError("max_file_uncompressed_size must be positive")
    if max_compression_ratio is not None and max_compression_ratio <= 0:
        raise ValueError("max_compression_ratio must be positive or None")


def _sanitize_archive_entry_name(raw_name: str, *, archive_type: str) -> str:
    normalized = raw_name.replace("\\", "/")
    for char in normalized:
        if char < "\x20" or char == "\x7f":
            # NUL ucinał nazwę w `zipfile`/`tarfile` (a w nagłówku PAX `path`
            # dochodził do `stat` jako surowy „embedded null character in path"),
            # a `\x01`/`\x7f` trafiały wprost do rozpakowywanych ścieżek.
            raise ValueError(
                f"{archive_type} entry path contains a control character (U+{ord(char):04X})"
            )
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise ValueError(f"{archive_type} entry path must be relative")
    if not path.parts:
        # `""`, `"."` i `"./"` normalizują się do `"."`, czyli do katalogu
        # bieżącego — wpis bez nazwy przechodził dalej jako `"."`.
        raise ValueError(f"{archive_type} entry path must not be empty")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{archive_type} entry path contains unsafe segments")
    if ":" in normalized:
        raise ValueError(f"{archive_type} entry path contains drive separator")
    return path.as_posix()
