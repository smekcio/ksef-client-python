from __future__ import annotations

import re

from .ksef_number import ValidationResult

CERTIFICATE_SERIAL_NUMBER_PATTERN = re.compile(r"^[0-9A-F]{16}$")


def validate_certificate_serial_number(serial_number: str) -> ValidationResult:
    if not serial_number:
        return ValidationResult(False, "empty value")

    if not CERTIFICATE_SERIAL_NUMBER_PATTERN.match(serial_number):
        return ValidationResult(False, "invalid format")

    return ValidationResult(True, "ok")


def is_valid_certificate_serial_number(serial_number: str) -> bool:
    return validate_certificate_serial_number(serial_number).is_valid


def require_certificate_serial_number(serial_number: str) -> str:
    result = validate_certificate_serial_number(serial_number)
    if not result.is_valid:
        raise ValueError(f"Invalid certificate serial number: {result.message}")
    return serial_number
