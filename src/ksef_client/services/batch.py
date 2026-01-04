from __future__ import annotations

from typing import List

from .crypto import encrypt_aes_cbc_pkcs7, get_file_metadata
from ..utils.zip_utils import split_bytes, MAX_BATCH_PART_SIZE_BYTES


def build_batch_file_info(zip_bytes: bytes, encrypted_parts: List[bytes]) -> dict:
    zip_meta = get_file_metadata(zip_bytes)
    file_parts = []
    for idx, part in enumerate(encrypted_parts, start=1):
        part_meta = get_file_metadata(part)
        file_parts.append(
            {
                "ordinalNumber": idx,
                "fileSize": part_meta.file_size,
                "fileHash": part_meta.sha256_base64,
            }
        )
    return {
        "fileSize": zip_meta.file_size,
        "fileHash": zip_meta.sha256_base64,
        "fileParts": file_parts,
    }


def encrypt_batch_parts(
    zip_bytes: bytes,
    key: bytes,
    iv: bytes,
    *,
    max_part_size: int = MAX_BATCH_PART_SIZE_BYTES,
) -> tuple[List[bytes], dict]:
    parts = split_bytes(zip_bytes, max_part_size=max_part_size)
    encrypted_parts = [encrypt_aes_cbc_pkcs7(part, key, iv) for part in parts]
    batch_file_info = build_batch_file_info(zip_bytes, encrypted_parts)
    return encrypted_parts, batch_file_info
