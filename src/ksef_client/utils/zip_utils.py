from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import PurePosixPath

MAX_BATCH_PART_SIZE_BYTES = 100 * 1024 * 1024
_DETERMINISTIC_ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_DETERMINISTIC_TAR_MTIME = 0


def build_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
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
        for name, content in files.items():
            safe_name = _sanitize_archive_entry_name(name, archive_type="tar.gz")
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


def split_bytes(data: bytes, max_part_size: int = MAX_BATCH_PART_SIZE_BYTES) -> list[bytes]:
    if max_part_size <= 0:
        raise ValueError("max_part_size must be positive")
    if len(data) <= max_part_size:
        return [data]
    parts = []
    for offset in range(0, len(data), max_part_size):
        parts.append(data[offset : offset + max_part_size])
    return parts


def unzip_bytes(
    data: bytes,
    *,
    max_files: int = 10_000,
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
    max_files: int = 10_000,
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
    max_files: int = 10_000,
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
            if member.size > max_file_uncompressed_size:
                raise ValueError("tar.gz contains an entry exceeding max_file_uncompressed_size")

            total_uncompressed += int(member.size)
            if total_uncompressed > max_total_uncompressed_size:
                raise ValueError("tar.gz exceeds max_total_uncompressed_size")
            if (
                max_compression_ratio is not None
                and total_uncompressed / compressed_size > max_compression_ratio
            ):
                raise ValueError("tar.gz exceeds max_compression_ratio")

            safe_name = _sanitize_archive_entry_name(member.name, archive_type="tar.gz")
            extracted = tf.extractfile(member)
            if extracted is None:
                raise ValueError("tar.gz entry could not be read")
            result[safe_name] = extracted.read()
    return result


def unzip_bytes_safe(
    data: bytes,
    *,
    max_files: int = 10_000,
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
            if info.is_dir():
                continue

            if len(result) >= max_files:
                raise ValueError("zip contains too many files")

            if info.file_size > max_file_uncompressed_size:
                raise ValueError("zip contains an entry exceeding max_file_uncompressed_size")

            total_uncompressed += int(info.file_size)
            if total_uncompressed > max_total_uncompressed_size:
                raise ValueError("zip exceeds max_total_uncompressed_size")

            if max_compression_ratio is not None:
                compressed = int(info.compress_size or 0)
                uncompressed = int(info.file_size or 0)
                if compressed == 0 and uncompressed > 0:
                    raise ValueError("zip entry has suspicious compression metadata")
                if compressed > 0 and uncompressed > 0:
                    ratio = uncompressed / compressed
                    if ratio > max_compression_ratio:
                        raise ValueError("zip entry exceeds max_compression_ratio")

            safe_name = _sanitize_archive_entry_name(info.filename, archive_type="zip")
            result[safe_name] = zf.read(info.filename)
    return result


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
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise ValueError(f"{archive_type} entry path must be relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{archive_type} entry path contains unsafe segments")
    if ":" in normalized:
        raise ValueError(f"{archive_type} entry path contains drive separator")
    return path.as_posix()
