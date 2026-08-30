from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from ksef_client import models as m
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.cli.sdk import adapters
from ksef_client.utils.collective_identifier import require_invoices_query_identifiers

_KSEF = "5265877635-20250826-0100001AF629-AF"
_IZ = "1111111111-IZ202607-65ED02180000-E7"


class _FakeClient:
    def __init__(self, collective_identifiers) -> None:
        self.collective_identifiers = collective_identifiers

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)


def _patch_client(monkeypatch, collective) -> None:
    monkeypatch.setattr(adapters, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(
        adapters,
        "create_client",
        lambda base_url, access_token=None: _FakeClient(collective),
    )


def test_generate_collective_identifier_success(monkeypatch) -> None:
    class _Collective:
        def generate_for_ksef_numbers(
            self, numbers, *, access_token, descriptions=None, max_invoices=None
        ):
            _ = (access_token, descriptions, max_invoices)
            assert numbers == [_KSEF]
            return m.GenerateCollectiveIdentifierResponse(collective_identifier_number=_IZ)

    _patch_client(monkeypatch, _Collective())
    result = adapters.generate_collective_identifier(
        profile="demo",
        base_url="https://example.invalid",
        ksef_numbers=[_KSEF],
    )
    assert result["collectiveIdentifierNumber"] == _IZ


def test_generate_collective_identifier_from_file_and_empty_errors(
    monkeypatch, tmp_path: Path
) -> None:
    with pytest.raises(CliError) as empty:
        adapters.generate_collective_identifier(
            profile="demo",
            base_url="https://example.invalid",
            ksef_numbers=[],
        )
    assert empty.value.code == ExitCode.VALIDATION_ERROR

    missing = tmp_path / "missing.txt"
    with pytest.raises(CliError) as missing_exc:
        adapters.generate_collective_identifier(
            profile="demo",
            base_url="https://example.invalid",
            ksef_numbers=[],
            from_file=str(missing),
        )
    assert missing_exc.value.code == ExitCode.IO_ERROR

    blank = tmp_path / "blank.txt"
    blank.write_text("# only comments\n\n", encoding="utf-8")
    with pytest.raises(CliError) as blank_exc:
        adapters.generate_collective_identifier(
            profile="demo",
            base_url="https://example.invalid",
            ksef_numbers=[],
            from_file=str(blank),
        )
    assert blank_exc.value.code == ExitCode.VALIDATION_ERROR

    numbers_file = tmp_path / "ksef.txt"
    numbers_file.write_text(f"{_KSEF}\n# skip\n", encoding="utf-8")

    class _Collective:
        def generate_for_ksef_numbers(
            self, numbers, *, access_token, descriptions=None, max_invoices=None
        ):
            _ = (access_token, descriptions, max_invoices)
            assert numbers == [_KSEF]
            return {"collectiveIdentifierNumber": _IZ}

    _patch_client(monkeypatch, _Collective())
    result = adapters.generate_collective_identifier(
        profile="demo",
        base_url="https://example.invalid",
        ksef_numbers=[],
        from_file=str(numbers_file),
    )
    assert result["collectiveIdentifierNumber"] == _IZ


def test_generate_collective_identifier_wraps_value_error(monkeypatch) -> None:
    class _Collective:
        def generate_for_ksef_numbers(
            self, numbers, *, access_token, descriptions=None, max_invoices=None
        ):
            _ = (numbers, access_token, descriptions, max_invoices)
            raise ValueError("too many invoices")

    _patch_client(monkeypatch, _Collective())
    with pytest.raises(CliError) as exc:
        adapters.generate_collective_identifier(
            profile="demo",
            base_url="https://example.invalid",
            ksef_numbers=[_KSEF],
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR
    assert "too many invoices" in exc.value.message


def test_query_collective_identifiers_pages(monkeypatch) -> None:
    seen: dict[str, object] = {}
    item = m.CollectiveIdentifiersQueryResponseItem(
        collective_identifier_number=_IZ,
        created_in_current_context=True,
        date_created="2026-07-01T00:00:00Z",
        invoice_count=1,
    )

    class _Collective:
        def iter_query(self, request, *, access_token, page_size=None, continuation_token=None):
            _ = (request, access_token, page_size)
            seen["iter_token"] = continuation_token
            yield item

        def query(self, request, *, access_token, page_size=None, continuation_token=None):
            _ = (request, access_token, page_size)
            seen["query_token"] = continuation_token
            return m.CollectiveIdentifiersQueryResponse(
                collective_identifiers=[item],
                continuation_token=None,
            )

    _patch_client(monkeypatch, _Collective())
    paged = adapters.query_collective_identifiers(
        profile="demo",
        base_url="https://example.invalid",
        date_from="2026-01-01",
        date_to="2026-01-31",
        page_size=10,
        fetch_all=False,
        continuation_token="resume-query",
    )
    assert paged["count"] == 1
    assert paged["continuation_token"] == ""
    assert seen["query_token"] == "resume-query"

    all_pages = adapters.query_collective_identifiers(
        profile="demo",
        base_url="https://example.invalid",
        date_from="2026-01-01",
        date_to="2026-01-31",
        collective_identifier_number=_IZ,
        page_size=10,
        fetch_all=True,
        continuation_token="resume-iterator",
    )
    assert all_pages["count"] == 1
    assert all_pages["continuation_token"] == ""
    assert seen["iter_token"] == "resume-iterator"


def test_query_collective_identifiers_wraps_value_error(monkeypatch) -> None:
    class _Collective:
        def query(self, request, *, access_token, page_size=None, continuation_token=None):
            _ = (request, access_token, page_size, continuation_token)
            raise ValueError("range too wide")

    _patch_client(monkeypatch, _Collective())
    with pytest.raises(CliError) as exc:
        adapters.query_collective_identifiers(
            profile="demo",
            base_url="https://example.invalid",
            date_from="2026-01-01",
            date_to="2026-01-31",
            page_size=10,
            fetch_all=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_list_collective_identifier_invoices(monkeypatch) -> None:
    seen: dict[str, object] = {}
    invoice = m.CollectiveIdentifierInvoicesQueryResponseItem(
        collective_identifier_number=_IZ,
        details_hidden=False,
        ksef_number=_KSEF,
    )

    class _Collective:
        def list_invoices(
            self, iz_number, *, access_token, page_size=None, continuation_token=None
        ):
            _ = (iz_number, access_token, page_size)
            seen["list_token"] = continuation_token
            return m.CollectiveIdentifierInvoicesQueryResponse(
                invoices=[invoice],
                continuation_token="more",
            )

        def iter_invoices(
            self, iz_number, *, access_token, page_size=None, continuation_token=None
        ):
            _ = (iz_number, access_token, page_size)
            seen["iter_token"] = continuation_token
            yield invoice
            yield SimpleNamespace(ksef_number="raw")

    _patch_client(monkeypatch, _Collective())
    with pytest.raises(CliError) as empty:
        adapters.list_collective_identifier_invoices(
            profile="demo",
            base_url="https://example.invalid",
            iz_numbers=[],
            page_size=10,
            fetch_all=False,
        )
    assert empty.value.code == ExitCode.VALIDATION_ERROR

    paged = adapters.list_collective_identifier_invoices(
        profile="demo",
        base_url="https://example.invalid",
        iz_numbers=[_IZ],
        page_size=10,
        fetch_all=False,
        continuation_token="resume-invoices",
    )
    assert paged["count"] == 1
    assert paged["items"][0]["collectiveIdentifierNumber"] == _IZ
    assert paged["continuation_token"] == "more"
    assert seen["list_token"] == "resume-invoices"

    all_pages = adapters.list_collective_identifier_invoices(
        profile="demo",
        base_url="https://example.invalid",
        iz_numbers=[_IZ],
        page_size=10,
        fetch_all=True,
        continuation_token="resume-invoice-iterator",
    )
    assert all_pages["count"] == 2
    assert all_pages["items"][1] == SimpleNamespace(ksef_number="raw")
    assert all_pages["continuation_token"] == ""
    assert seen["iter_token"] == "resume-invoice-iterator"


def test_list_collective_identifier_invoices_rejects_more_than_10(monkeypatch) -> None:
    class _Collective:
        def list_invoices(
            self, iz_number, *, access_token, page_size=None, continuation_token=None
        ):
            _ = (access_token, page_size, continuation_token)
            require_invoices_query_identifiers(iz_number)
            raise AssertionError("should not call API")

    _patch_client(monkeypatch, _Collective())
    with pytest.raises(CliError) as exc:
        adapters.list_collective_identifier_invoices(
            profile="demo",
            base_url="https://example.invalid",
            iz_numbers=[_IZ] * 11,
            page_size=10,
            fetch_all=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR
    assert "10" in exc.value.message


def test_list_collective_identifier_invoices_wraps_value_error(monkeypatch) -> None:
    class _Collective:
        def list_invoices(
            self, iz_number, *, access_token, page_size=None, continuation_token=None
        ):
            _ = (iz_number, access_token, page_size, continuation_token)
            raise ValueError("bad iz")

    _patch_client(monkeypatch, _Collective())
    with pytest.raises(CliError) as exc:
        adapters.list_collective_identifier_invoices(
            profile="demo",
            base_url="https://example.invalid",
            iz_numbers=[_IZ],
            page_size=10,
            fetch_all=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR


def test_list_collective_identifiers_by_ksef_number(monkeypatch) -> None:
    seen: dict[str, object] = {}
    item = m.CollectiveIdentifiersByKsefNumberQueryResponseItem(
        collective_identifier_number=_IZ,
        created_in_current_context=True,
        date_created="2026-07-01T00:00:00Z",
    )

    class _Collective:
        def list_by_ksef_number(
            self, ksef_number, *, access_token, page_size=None, continuation_token=None
        ):
            _ = (ksef_number, access_token, page_size)
            seen["list_token"] = continuation_token
            return m.CollectiveIdentifiersByKsefNumberQueryResponse(
                collective_identifiers=[item],
                continuation_token="more",
            )

        def iter_by_ksef_number(
            self, ksef_number, *, access_token, page_size=None, continuation_token=None
        ):
            _ = (ksef_number, access_token, page_size)
            seen["iter_token"] = continuation_token
            yield item

    _patch_client(monkeypatch, _Collective())
    paged = adapters.list_collective_identifiers_by_ksef_number(
        profile="demo",
        base_url="https://example.invalid",
        ksef_number=_KSEF,
        page_size=10,
        fetch_all=False,
        continuation_token="resume-by-ksef",
    )
    assert paged["continuation_token"] == "more"
    assert paged["count"] == 1
    assert seen["list_token"] == "resume-by-ksef"

    all_pages = adapters.list_collective_identifiers_by_ksef_number(
        profile="demo",
        base_url="https://example.invalid",
        ksef_number=_KSEF,
        page_size=10,
        fetch_all=True,
        continuation_token="resume-by-ksef-iterator",
    )
    assert all_pages["continuation_token"] == ""
    assert all_pages["count"] == 1
    assert seen["iter_token"] == "resume-by-ksef-iterator"


def test_list_collective_identifiers_by_ksef_number_wraps_value_error(monkeypatch) -> None:
    class _Collective:
        def list_by_ksef_number(
            self, ksef_number, *, access_token, page_size=None, continuation_token=None
        ):
            _ = (ksef_number, access_token, page_size, continuation_token)
            raise ValueError("bad ksef")

    _patch_client(monkeypatch, _Collective())
    with pytest.raises(CliError) as exc:
        adapters.list_collective_identifiers_by_ksef_number(
            profile="demo",
            base_url="https://example.invalid",
            ksef_number=_KSEF,
            page_size=10,
            fetch_all=False,
        )
    assert exc.value.code == ExitCode.VALIDATION_ERROR
