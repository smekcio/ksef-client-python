"""Measure export RSS in fresh processes: 50/500 MiB, with disk-backed encrypted parts.

Run with the source checkout on PYTHONPATH. Test artifacts stay under --directory.
The producer and measured consumer use different processes, so fixture creation
cannot conceal growth of the transfer/decrypt/extract pipeline's peak RSS.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import importlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ksef_client import KsefClientOptions
from ksef_client import models as m
from ksef_client.http import BaseHttpClient
from ksef_client.operations import OperationState
from ksef_client.streaming_export import BUFFER_SIZE, ExportOperation, digest

KEY, IV = b"k" * 32, b"i" * 16


def peak_rss() -> int:
    if os.name != "nt":
        resource = importlib.import_module("resource")

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (
            1 if sys.platform == "darwin" else 1024
        )

    class Memory(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            *[
                (n, ctypes.c_size_t)
                for n in (
                    "PeakWorkingSetSize",
                    "WorkingSetSize",
                    "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage",
                    "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage",
                    "PagefileUsage",
                    "PeakPagefileUsage",
                )
            ],
        ]

    memory = Memory()
    memory.cb = ctypes.sizeof(memory)
    # Pseudo handle does not require CloseHandle and avoids pointer-size truncation.
    if not ctypes.windll.psapi.GetProcessMemoryInfo(
        ctypes.c_void_p(-1), ctypes.byref(memory), memory.cb
    ):
        raise OSError("Cannot read process memory")
    return memory.PeakWorkingSetSize


def build(directory: Path, size_mib: int) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    archive = directory / "source.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zipped:
        for index in range(size_mib // 50):
            with zipped.open(f"invoice-{index}.xml", "w") as output:
                for _ in range(50):
                    output.write(b"x" * BUFFER_SIZE)
        zipped.writestr("_metadata.json", b'{"invoices":[]}')
    parts = []
    with archive.open("rb") as source:
        ordinal = 0
        while source.tell() < archive.stat().st_size:
            ordinal += 1
            file = directory / f"source-{ordinal}.bin"
            enc = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
            pad = padding.PKCS7(128).padder()
            sha = hashlib.sha256()
            size = 0
            with file.open("wb") as output:
                for _ in range(50):
                    chunk = source.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    sha.update(chunk)
                    output.write(enc.update(pad.update(chunk)))
                output.write(enc.update(pad.finalize()) + enc.finalize())
            encrypted_size, encrypted_hash = digest(file)
            parts.append(
                m.InvoicePackagePart(
                    encrypted_part_hash=encrypted_hash,
                    encrypted_part_size=encrypted_size,
                    expiration_date="2099-01-01",
                    method="GET",
                    ordinal_number=ordinal,
                    part_hash=base64.b64encode(sha.digest()).decode(),
                    part_name=file.name,
                    part_size=size,
                    url=f"https://storage.example.test/{file.name}",
                )
            )
    package = m.InvoicePackage(
        compression_type=m.CompressionType.ZIP,
        invoice_count=size_mib // 50,
        is_truncated=False,
        parts=parts,
        size=archive.stat().st_size,
    )
    (directory / "package.json").write_text(json.dumps(package.to_dict()), encoding="utf-8")


def measure(directory: Path) -> None:
    package = m.InvoicePackage.from_dict(json.loads((directory / "package.json").read_text()))

    class FileStream(httpx.SyncByteStream):
        def __init__(self, file: Path) -> None:
            self.file = file

        def __iter__(self):
            with self.file.open("rb") as source:
                while chunk := source.read(BUFFER_SIZE):
                    yield chunk

    class Transport(httpx.BaseTransport):
        def handle_request(self, request):
            part = next(
                p for p in package.parts if p.part_name == request.url.path.removeprefix("/")
            )
            return httpx.Response(
                200,
                headers={"x-ms-meta-hash": part.encrypted_part_hash},
                stream=FileStream(directory / part.part_name),
            )

    options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    client = BaseHttpClient(options)
    client._client.close()
    client._client = httpx.Client(transport=Transport())
    owner: Any = SimpleNamespace(
        options=options,
        api=SimpleNamespace(
            http_client=client,
            invoices=SimpleNamespace(
                get_export_status=lambda ref: m.InvoiceExportStatusResponse.from_dict(
                    {"status": {"code": 200, "description": "ready"}, "package": package.to_dict()}
                )
            ),
        ),
    )
    state = OperationState(
        "export",
        "benchmark",
        "DUMMY",
        "EXPORT",
        {"key": base64.b64encode(KEY).decode(), "iv": base64.b64encode(IV).decode()},
    )
    try:
        result = ExportOperation(owner, state).download_to(
            directory / "result", work_dir=directory / "work", timeout=600
        )
        print(
            json.dumps(
                {"rss_bytes": peak_rss(), "files": len(result.files), "archive_bytes": package.size}
            )
        )
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--measure", action="store_true")
    args = parser.parse_args()
    if args.measure:
        measure(args.directory)
        return
    results = []
    for size in (50, 500):
        target = args.directory.resolve() / str(size)
        build(target, size)
        output = subprocess.check_output(
            [sys.executable, __file__, "--measure", "--directory", str(target)], text=True
        )
        results.append(json.loads(output))
    delta = results[1]["rss_bytes"] - results[0]["rss_bytes"]
    print(
        json.dumps(
            {"results": results, "rss_delta_bytes": delta, "passed": delta <= 32 * 1024 * 1024},
            indent=2,
        )
    )
    if delta > 32 * 1024 * 1024:
        raise SystemExit("RSS growth exceeds 32 MiB")


if __name__ == "__main__":
    main()
