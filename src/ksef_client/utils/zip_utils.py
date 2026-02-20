from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath

MAX_BATCH_PART_SIZE_BYTES = 100 * 1024 * 1024


def build_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
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


def unzip_bytes_safe(
    data: bytes,
    *,
    max_files: int = 10_000,
    max_total_uncompressed_size: int = 2_000_000_000,
    max_file_uncompressed_size: int = 500_000_000,
    max_compression_ratio: float | None = 200.0,
) -> dict[str, bytes]:
    if max_files <= 0:
        raise ValueError("max_files must be positive")
    if max_total_uncompressed_size <= 0:
        raise ValueError("max_total_uncompressed_size must be positive")
    if max_file_uncompressed_size <= 0:
        raise ValueError("max_file_uncompressed_size must be positive")
    if max_compression_ratio is not None and max_compression_ratio <= 0:
        raise ValueError("max_compression_ratio must be positive or None")

    result: dict[str, bytes] = {}

    def _sanitize_zip_entry_name(raw_name: str) -> str:
        normalized = raw_name.replace("\\", "/")
        path = PurePosixPath(normalized)
        if path.is_absolute():
            raise ValueError("zip entry path must be relative")
        if any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("zip entry path contains unsafe segments")
        if ":" in normalized:
            raise ValueError("zip entry path contains drive separator")
        return path.as_posix()

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

            safe_name = _sanitize_zip_entry_name(info.filename)
            result[safe_name] = zf.read(info.filename)
    return result
