from __future__ import annotations

import re

from .ksef_number import ValidationResult, _crc8

COLLECTIVE_IDENTIFIER_PATTERN = re.compile(
    r"^(\d{10})-IZ(\d{4})(0[1-9]|1[0-2])-([0-9A-F]{12})-([0-9A-F]{2})$"
)


def validate_collective_identifier_number(
    collective_identifier_number: str,
) -> ValidationResult:
    if not collective_identifier_number:
        return ValidationResult(False, "empty value")

    if not COLLECTIVE_IDENTIFIER_PATTERN.match(collective_identifier_number):
        return ValidationResult(False, "invalid format")

    data_part = collective_identifier_number[:32]
    checksum = collective_identifier_number[-2:]
    expected = f"{_crc8(data_part.encode('ascii')):02X}"
    if expected != checksum:
        return ValidationResult(False, f"checksum mismatch (expected {expected})")

    return ValidationResult(True, "ok")


def is_valid_collective_identifier_number(collective_identifier_number: str) -> bool:
    return validate_collective_identifier_number(collective_identifier_number).is_valid


def require_collective_identifier_number(collective_identifier_number: str) -> str:
    result = validate_collective_identifier_number(collective_identifier_number)
    if not result.is_valid:
        raise ValueError(
            f"Invalid collective identifier number: {result.message}"
        )
    return collective_identifier_number
