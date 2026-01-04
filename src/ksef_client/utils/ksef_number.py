from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Tuple

KSEF_NUMBER_PATTERN = re.compile(
    r"^([1-9](\d[1-9]|[1-9]\d)\d{7})-"
    r"(20[2-9][0-9]|2[1-9]\d{2}|[3-9]\d{3})"
    r"(0[1-9]|1[0-2])"
    r"(0[1-9]|[12]\d|3[01])"
    r"-([0-9A-F]{6})-?([0-9A-F]{6})-([0-9A-F]{2})$"
)


@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    message: str


def _crc8(data: bytes) -> int:
    poly = 0x07
    crc = 0x00
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def validate_ksef_number(ksef_number: str) -> ValidationResult:
    if not ksef_number:
        return ValidationResult(False, "empty value")

    match = KSEF_NUMBER_PATTERN.match(ksef_number)
    if not match:
        return ValidationResult(False, "invalid format")

    normalized = ksef_number
    if len(normalized) == 36:
        # Remove optional hyphen between the 6+6 technical parts to keep 35 chars.
        parts = normalized.split("-")
        if len(parts) == 5:
            normalized = "-".join([parts[0], parts[1], parts[2] + parts[3], parts[4]])
        else:
            return ValidationResult(False, "invalid parts")

    if len(normalized) != 35:
        return ValidationResult(False, "invalid length")

    data_part = normalized[:32]
    checksum = normalized[-2:]
    crc = _crc8(data_part.encode("ascii"))
    expected = f"{crc:02X}"
    if expected != checksum:
        return ValidationResult(False, f"checksum mismatch (expected {expected})")

    return ValidationResult(True, "ok")


def is_valid_ksef_number(ksef_number: str) -> bool:
    return validate_ksef_number(ksef_number).is_valid
