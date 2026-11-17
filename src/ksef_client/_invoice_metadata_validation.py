"""Validate known archive metadata fields before permissive model conversion."""

from __future__ import annotations

import math
from typing import Any

_TEXT_FIELDS = (
    "acquisitionDate",
    "currency",
    "hashOfCorrectedInvoice",
    "invoiceHash",
    "invoiceNumber",
    "invoiceType",
    "invoicingDate",
    "invoicingMode",
    "issueDate",
    "ksefNumber",
    "permanentStorageDate",
)


def _object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError("Invalid invoice metadata object")
    return value


def _validate_strings(value: dict[str, Any], *fields: str) -> None:
    if any(value.get(field) is not None and type(value[field]) is not str for field in fields):
        raise ValueError("Invalid invoice metadata string")


def _validate_party(value: Any, kind: str) -> None:
    party = _object(value)
    _validate_strings(party, "name")
    if kind in {"seller", "authorizedSubject"}:
        _validate_strings(party, "nip")
    if kind in {"authorizedSubject", "thirdSubject"}:
        role = party.get("role")
        if role is not None and type(role) is not int:
            raise ValueError("Invalid invoice metadata party role")
    if kind in {"buyer", "thirdSubject"}:
        identifier = party.get("identifier")
        if identifier is not None:
            _validate_strings(_object(identifier), "type", "value")


def _validate_archive_metadata(value: dict[str, Any]) -> None:
    _validate_strings(value, *_TEXT_FIELDS)
    for field in ("netAmount", "vatAmount", "grossAmount"):
        amount = value.get(field)
        if amount is not None and (type(amount) not in (int, float) or not math.isfinite(amount)):
            raise ValueError("Invalid invoice metadata amount")
    for field in ("hasAttachment", "isSelfInvoicing"):
        flag = value.get(field)
        if flag is not None and type(flag) is not bool:
            raise ValueError("Invalid invoice metadata flag")
    for field in ("buyer", "seller", "authorizedSubject"):
        party = value.get(field)
        if party is not None:
            _validate_party(party, field)
    third_subjects = value.get("thirdSubjects")
    if third_subjects is not None:
        if type(third_subjects) is not list:
            raise ValueError("Invalid invoice metadata third subjects")
        for subject in third_subjects:
            _validate_party(subject, "thirdSubject")
    form = value.get("formCode")
    if form is not None:
        _validate_strings(_object(form), "systemCode", "schemaVersion", "value")
