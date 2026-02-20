import pytest

from ksef_client.cli.validation import require_exactly_one, validate_iso_date


def test_require_exactly_one_accepts_one() -> None:
    require_exactly_one({"a": True, "b": False}, "bad")


def test_require_exactly_one_rejects_many_or_zero() -> None:
    with pytest.raises(ValueError):
        require_exactly_one({"a": False, "b": False}, "bad")
    with pytest.raises(ValueError):
        require_exactly_one({"a": True, "b": True}, "bad")


def test_validate_iso_date() -> None:
    assert validate_iso_date("2026-01-01") == "2026-01-01"
