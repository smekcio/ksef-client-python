"""Validate actual ZIP directory entries before allocating ZipInfo objects."""

import io
import struct
import zipfile
from unittest.mock import Mock, patch

import pytest

from ksef_client import models as m
from ksef_client.streaming_export import (
    KsefExportTransferError,
    extract_archive,
    validate_zip_directory,
)


def zip_bytes(names, *, reported_count=None, zip64=False, prefix=b""):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"" if name.endswith("/") else b"invoice")
        archive.comment = b"archive comment"
    data = buffer.getvalue()
    offset = data.rfind(b"PK\x05\x06")
    end = bytearray(data[offset:])
    count = len(names) if reported_count is None else reported_count
    end[8:12] = struct.pack("<HH", count, count)
    if zip64:
        size, start = struct.unpack_from("<LL", end, 12)
        record = struct.pack(
            "<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, size, start
        )
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, offset, 1)
        end[8:20] = struct.pack("<HHLL", 65535, 65535, 0xFFFFFFFF, 0xFFFFFFFF)
        data = data[:offset] + record + locator + end
    else:
        data = data[:offset] + end
    return prefix + data


@pytest.mark.parametrize("zip64", [False, True])
@pytest.mark.parametrize("directory", [False, True])
def test_actual_entry_limit_is_enforced_before_zipfile_allocation(tmp_path, zip64, directory):
    names = [f"entry-{i}" + ("/" if directory else ".xml") for i in range(10002)]
    archive = tmp_path / "many.zip"
    archive.write_bytes(zip_bytes(names, reported_count=1, zip64=zip64))
    target = tmp_path / "result"
    target.mkdir()
    with (
        patch("zipfile.ZipFile", side_effect=AssertionError("allocated before validation")),
        pytest.raises(KsefExportTransferError, match="safety limits"),
    ):
        extract_archive(archive, target, m.CompressionType.ZIP)
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("zip64", [False, True])
@pytest.mark.parametrize("prefix", [b"", b"executable stub"])
@pytest.mark.parametrize("names", [[], ["folder/", "folder/invoice.xml"]])
def test_valid_directories_preserve_zip64_prefix_and_empty_archive(
    tmp_path, zip64, prefix, names, monkeypatch
):
    monkeypatch.setattr("ksef_client.streaming_export.EXPORT_MAX_ARCHIVE_ENTRIES", 2)
    archive = tmp_path / "valid.zip"
    archive.write_bytes(zip_bytes(names, zip64=zip64, prefix=prefix))
    target = tmp_path / "result"
    target.mkdir()
    assert extract_archive(archive, target, m.CompressionType.ZIP) == (
        ("folder/invoice.xml",) if names else ()
    )
    if names:
        assert (target / "folder/invoice.xml").read_bytes() == b"invoice"


@pytest.mark.parametrize("reported_count", [0, 2])
def test_mismatched_entry_count_is_rejected(reported_count):
    with pytest.raises(KsefExportTransferError, match="entry count"):
        validate_zip_directory(
            io.BytesIO(zip_bytes(["invoice.xml"], reported_count=reported_count))
        )


@pytest.mark.parametrize("prefix", [b"", b"executable stub"])
@pytest.mark.parametrize("over_limit", [False, True])
def test_zip64_validation_does_not_depend_on_stdlib_private_parser(monkeypatch, prefix, over_limit):
    data = zip_bytes(
        ["folder/", "folder/invoice.xml"],
        zip64=True,
        prefix=prefix,
        reported_count=1 if over_limit else None,
    )
    monkeypatch.setattr(zipfile, "_EndRecData", Mock(side_effect=AssertionError("private parser")))
    monkeypatch.setattr(
        "ksef_client.streaming_export.EXPORT_MAX_ARCHIVE_ENTRIES", 1 if over_limit else 2
    )
    if over_limit:
        with pytest.raises(KsefExportTransferError, match="safety limits"):
            validate_zip_directory(io.BytesIO(data))
    else:
        validate_zip_directory(io.BytesIO(data))


@pytest.mark.parametrize("corruption", ["offset", "short", "signature", "lengths", "size"])
def test_invalid_directory_is_rejected_before_parsing(corruption):
    data = bytearray(zip_bytes(["invoice.xml"]))
    end = data.rfind(b"PK\x05\x06")
    central = data.index(b"PK\x01\x02")
    if corruption in {"offset", "size"}:
        struct.pack_into("<L", data, end + 12, end + 1 if corruption == "offset" else 16777217)
    elif corruption == "short":
        struct.pack_into("<L", data, end + 12, 1)
    elif corruption == "signature":
        data[central] = 0
    else:
        struct.pack_into("<H", data, central + 28, 65535)
    with pytest.raises(KsefExportTransferError):
        validate_zip_directory(io.BytesIO(data))


@pytest.mark.parametrize(
    "corruption", ["split", "record-size", "record-signature", "locator-offset"]
)
def test_zip64_rejects_unsupported_or_inconsistent_end_records(corruption):
    data = bytearray(zip_bytes(["invoice.xml"], zip64=True))
    locator = data.rfind(b"PK\x06\x07")
    record = data.rfind(b"PK\x06\x06")
    if corruption == "split":
        struct.pack_into("<L", data, locator + 4, 1)
    elif corruption == "record-size":
        struct.pack_into("<Q", data, record + 4, 45)
    elif corruption == "record-signature":
        data[record] = 0
    else:
        struct.pack_into("<Q", data, locator + 8, len(data) + 1)
    with pytest.raises(KsefExportTransferError):
        validate_zip_directory(io.BytesIO(data))


def test_zip64_rejects_truncated_record():
    data = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)
    data += struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
    with pytest.raises(KsefExportTransferError, match="Truncated ZIP64"):
        validate_zip_directory(io.BytesIO(data))


@pytest.mark.parametrize(
    "corruption", ["comment", "split", "overreported-count", "directory-budget"]
)
def test_zip_rejects_bad_end_records_and_directory_budgets(corruption, monkeypatch):
    data = bytearray(zip_bytes(["invoice.xml"]))
    end = data.rfind(b"PK\x05\x06")
    if corruption == "comment":
        data.extend(b"trailing data")
    elif corruption == "split":
        struct.pack_into("<H", data, end + 4, 1)
    elif corruption == "overreported-count":
        struct.pack_into("<HH", data, end + 8, 10002, 10002)
    else:
        monkeypatch.setattr("ksef_client.streaming_export.BUFFER_SIZE", 1)
    with pytest.raises(KsefExportTransferError):
        validate_zip_directory(io.BytesIO(data))
