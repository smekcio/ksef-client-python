from __future__ import annotations

import copy
import json
import pickle

import pytest

from ksef_client import (
    ErrorCode,
    KsefCheckpointError,
    KsefDocumentError,
    KsefDocumentValidationError,
    KsefError,
    KsefRenderingError,
    KsefVerificationError,
)
from ksef_client.cli.exit_codes import ExitCode, exit_code_for_error
from ksef_client.documents.fa3 import (
    Fa3CurrencyMismatchError,
    FA3ParseError,
    FA3XmlValidationError,
)

DOCUMENT_ERROR_CLASSES: tuple[
    tuple[type[KsefDocumentError], ErrorCode, type[BaseException] | None], ...
] = (
    (KsefDocumentError, ErrorCode.DOCUMENT_ERROR, None),
    (KsefDocumentValidationError, ErrorCode.DOCUMENT_VALIDATION_FAILED, ValueError),
    (KsefRenderingError, ErrorCode.DOCUMENT_RENDERING_FAILED, RuntimeError),
    (KsefVerificationError, ErrorCode.VERIFICATION_FAILED, ValueError),
    (KsefCheckpointError, ErrorCode.CHECKPOINT_FAILED, RuntimeError),
)

LEGACY_ERROR_CLASSES: tuple[type[KsefDocumentValidationError], ...] = (
    FA3ParseError,
    FA3XmlValidationError,
    Fa3CurrencyMismatchError,
)

ALL_ERROR_CLASSES: tuple[type[KsefDocumentError], ...] = (
    *(error_cls for error_cls, _, _ in DOCUMENT_ERROR_CLASSES),
    *LEGACY_ERROR_CLASSES,
)


@pytest.mark.parametrize(("error_cls", "code", "builtin"), DOCUMENT_ERROR_CLASSES)
def test_document_error_contract(
    error_cls: type[KsefDocumentError],
    code: ErrorCode,
    builtin: type[BaseException] | None,
) -> None:
    error = error_cls("boom", details=("first", "second"))

    assert isinstance(error, KsefError)
    assert isinstance(error, KsefDocumentError)
    assert error.code is code
    assert error.message == "boom"
    assert error.details == ("first", "second")
    assert str(error) == "boom"
    if builtin is not None:
        assert isinstance(error, builtin)

    payload = error.to_dict()

    assert payload["code"] == code.value
    assert payload["message"] == "boom"
    assert payload["details"] == ["first", "second"]
    assert payload["status_code"] is None
    assert "response_body" not in payload
    assert json.loads(json.dumps(payload)) == payload


def test_document_error_base_has_no_builtin_mixin() -> None:
    error = KsefDocumentError("boom")

    assert error.code is ErrorCode.DOCUMENT_ERROR
    assert not isinstance(error, (ValueError, RuntimeError))
    assert error.details == ()
    assert error.to_dict()["details"] == []


def test_document_error_omit_none() -> None:
    payload = KsefDocumentError("boom").to_dict(omit_none=True)

    assert "status_code" not in payload
    assert "retry_after" not in payload
    assert payload["details"] == []


@pytest.mark.parametrize("error_cls", LEGACY_ERROR_CLASSES)
def test_legacy_fa3_errors_are_document_validation_errors(
    error_cls: type[KsefDocumentValidationError],
) -> None:
    error = error_cls("bad xml")

    assert isinstance(error, KsefDocumentValidationError)
    assert isinstance(error, KsefDocumentError)
    assert isinstance(error, ValueError)
    assert error.code is ErrorCode.DOCUMENT_VALIDATION_FAILED
    with pytest.raises(KsefDocumentError):
        raise error
    with pytest.raises(ValueError):
        raise error


def test_fa3_parse_error_can_still_be_caught_by_its_own_class() -> None:
    with pytest.raises(FA3ParseError):
        raise FA3ParseError("bad xml")


def _pickle_roundtrip(error: KsefError) -> KsefError:
    return pickle.loads(pickle.dumps(error))


@pytest.mark.parametrize("error_cls", ALL_ERROR_CLASSES)
def test_document_errors_survive_pickle_and_copy(
    error_cls: type[KsefDocumentError],
) -> None:
    error = error_cls("boom", details=("detail",))

    for restored in (
        copy.copy(error),
        copy.deepcopy(error),
        _pickle_roundtrip(error),
    ):
        assert type(restored) is error_cls
        assert restored.to_dict() == error.to_dict()


@pytest.mark.parametrize(
    ("code", "exit_code"),
    [
        (ErrorCode.DOCUMENT_ERROR, ExitCode.API_ERROR),
        (ErrorCode.DOCUMENT_VALIDATION_FAILED, ExitCode.VALIDATION_ERROR),
        (ErrorCode.DOCUMENT_RENDERING_FAILED, ExitCode.API_ERROR),
        (ErrorCode.VERIFICATION_FAILED, ExitCode.VALIDATION_ERROR),
        (ErrorCode.CHECKPOINT_FAILED, ExitCode.IO_ERROR),
    ],
)
def test_document_error_exit_codes(code: ErrorCode, exit_code: ExitCode) -> None:
    error_cls = type("_Error", (KsefError,), {"code": code})

    assert exit_code_for_error(error_cls("x")) is exit_code
