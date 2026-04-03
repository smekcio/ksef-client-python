from __future__ import annotations

from ..models import BatchFileInfo, BatchFilePartInfo
from ..utils.zip_utils import MAX_BATCH_PART_SIZE_BYTES, split_bytes
from .crypto import encrypt_aes_cbc_pkcs7, get_file_metadata


def build_batch_file_info(zip_bytes: bytes, encrypted_parts: list[bytes]) -> BatchFileInfo:
    zip_meta = get_file_metadata(zip_bytes)
    file_parts: list[BatchFilePartInfo] = []
    for idx, part in enumerate(encrypted_parts, start=1):
        part_meta = get_file_metadata(part)
        file_parts.append(
            BatchFilePartInfo(
                ordinal_number=idx,
                file_size=part_meta.file_size,
                file_hash=part_meta.sha256_base64,
            )
        )
    return BatchFileInfo(
        file_size=zip_meta.file_size,
        file_hash=zip_meta.sha256_base64,
        file_parts=file_parts,
    )


def encrypt_batch_parts(
    zip_bytes: bytes,
    key: bytes,
    iv: bytes,
    *,
    max_part_size: int = MAX_BATCH_PART_SIZE_BYTES,
) -> tuple[list[bytes], BatchFileInfo]:
    parts = split_bytes(zip_bytes, max_part_size=max_part_size)
    encrypted_parts = [encrypt_aes_cbc_pkcs7(part, key, iv) for part in parts]
    batch_file_info = build_batch_file_info(zip_bytes, encrypted_parts)
    return encrypted_parts, batch_file_info
