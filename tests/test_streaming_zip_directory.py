"""Validate actual ZIP directory entries before allocating ZipInfo objects."""

import io
import struct
import zipfile
from typing import Any
from unittest.mock import patch

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


@pytest.mark.parametrize("record_signature", [b"PK\x05\x06", b"PK\x06\x06"])
@pytest.mark.parametrize("prefix", [b"", b"executable stub"])
@pytest.mark.parametrize("over_limit", [False, True])
def test_zip64_directory_handles_both_stdlib_location_conventions(
    monkeypatch, record_signature, prefix, over_limit
):
    data = zip_bytes(["folder/", "folder/invoice.xml"], zip64=True, prefix=prefix)
    zip_module: Any = zipfile
    end_record = zip_module._EndRecData(io.BytesIO(data))
    end_record[9] = data.rfind(record_signature)
    monkeypatch.setattr(zipfile, "_EndRecData", lambda source: end_record)
    monkeypatch.setattr(
        "ksef_client.streaming_export.EXPORT_MAX_ARCHIVE_ENTRIES", 1 if over_limit else 2
    )
    if over_limit:
        # Underreporting must still be rejected for either stdlib convention.
        end_record[4] = 1
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
