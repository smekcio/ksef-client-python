"""Bounded-memory export downloads with verified, byte-resumable disk checkpoints."""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import hashlib
import importlib
import json
import os
import re
import stat
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import IO, Any, BinaryIO

import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import models as m
from .exceptions import ErrorCode, KsefError
from .http import _validate_presigned_url_security, _wire_timeout
from .operations import AsyncOperation, Operation, OperationState
from .rate_limiting import CancellationToken
from .request_control import current_request_control, request_control, wait_seconds
from .utils.zip_utils import EXPORT_MAX_ARCHIVE_ENTRIES, _sanitize_archive_entry_name

BUFFER_SIZE = 1024 * 1024


class KsefExportTransferError(KsefError):
    code = ErrorCode.EXPORT_ERROR


def check_control() -> None:
    control = current_request_control()
    if control is not None:
        control.check()


def safe_path(path: Path) -> Path:
    absolute = path.absolute()
    for item in (absolute, *absolute.parents):
        if item.is_symlink() or (
            item.exists() and getattr(item.lstat(), "st_file_attributes", 0) & 1024
        ):
            raise KsefExportTransferError(
                "Links and reparse points are not allowed in export paths"
            )
    return absolute


@contextmanager
def directory_lock(directory: Path) -> Iterator[None]:
    """OS lock is released even if the process dies; the marker contains no secrets."""
    path = safe_path(directory / ".lock")
    with path.open("a+b") as stream:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            stream.write(b"0")
            stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl = importlib.import_module("fcntl")

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    safe_path(path)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".checkpoint-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def digest(path: Path) -> tuple[int, str]:
    size, sha = 0, hashlib.sha256()
    with safe_path(path).open("rb") as source:
        while chunk := source.read(BUFFER_SIZE):
            check_control()
            size += len(chunk)
            sha.update(chunk)
    return size, base64.b64encode(sha.digest()).decode()


def part_identity(part: m.InvoicePackagePart) -> dict[str, Any]:
    if (
        type(part.ordinal_number) is not int
        or not 1 <= part.ordinal_number <= 10001
        or part.method != "GET"
        or type(part.encrypted_part_size) is not int
        or part.encrypted_part_size <= 0
        or type(part.part_size) is not int
        or part.part_size <= 0
    ):
        raise KsefExportTransferError("Invalid export part descriptor")
    for value in (part.encrypted_part_hash, part.part_hash):
        try:
            if len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError("hash")
        except (ValueError, TypeError):
            raise KsefExportTransferError("Invalid export part hash") from None
    return {
        "ordinal": part.ordinal_number,
        "encrypted_size": part.encrypted_part_size,
        "encrypted_hash": part.encrypted_part_hash,
        "size": part.part_size,
        "hash": part.part_hash,
    }


def package_identity(package: m.InvoicePackage) -> list[dict[str, Any]]:
    if len(package.parts) > 10001:
        raise KsefExportTransferError("Too many export parts")
    parts = sorted(package.parts, key=lambda part: part.ordinal_number)
    if [p.ordinal_number for p in parts] != list(range(1, len(parts) + 1)):
        raise KsefExportTransferError("Export part sequence is invalid")
    if package.invoice_count and not parts:
        raise KsefExportTransferError("Nonempty export has no parts")
    return [part_identity(part) for part in parts]


@dataclass(frozen=True)
class ExportFiles:
    destination: Path
    files: tuple[str, ...]
    metadata_path: Path | None = field(repr=False)
    package: m.InvoicePackage = field(repr=False)


class ExportOperation(Operation[m.InvoiceExportStatusResponse]):
    def __init__(self, owner: Any, state: OperationState) -> None:
        self.owner = owner
        try:
            self._key = base64.b64decode(state.payload["key"], validate=True)
            self._iv = base64.b64decode(state.payload["iv"], validate=True)
            if len(self._key) != 32 or len(self._iv) != 16:
                raise ValueError("key size")
        except (KeyError, ValueError, TypeError):
            raise ValueError("Invalid export encryption state") from None
        super().__init__(
            state, lambda: owner.api.invoices.get_export_status(state.reference_number)
        )

    @contextmanager
    def _stream(
        self, part: m.InvoicePackagePart, headers: dict[str, str]
    ) -> Iterator[httpx.Response]:
        _validate_presigned_url_security(self.owner.options, part.url)
        # Application credentials and cookies never cross the storage boundary.
        base_headers = {"Accept-Encoding": "identity", **headers}
        timeout = _wire_timeout(self.owner.options).get(
            "timeout", self.owner.options.timeout_seconds
        )
        try:
            request = httpx.Request(
                "GET",
                part.url,
                headers=base_headers,
                extensions={"timeout": httpx.Timeout(timeout).as_dict()},
            )
        except httpx.InvalidURL:
            raise KsefExportTransferError("Invalid storage URL") from None
        # Use the configured transport (including proxy/TLS) directly. Client.send
        # logs full signed URLs at INFO and applies cookies/auth/redirect handling.
        transport = self.owner.api.http_client._client._transport_for_url(request.url)
        response = transport.handle_request(request)
        response.request = request
        try:
            yield response
        finally:
            response.close()

    def _download_part(
        self, part: m.InvoicePackagePart, directory: Path, manifest: dict[str, Any]
    ) -> None:
        path = safe_path(directory / f"part-{part.ordinal_number}.bin")
        expected = (part.encrypted_part_size, part.encrypted_part_hash)
        if path.exists() and digest(path) == expected:
            return
        key = str(part.ordinal_number)
        saved = manifest["progress"].get(key, {})
        if type(saved) is not dict:
            raise KsefExportTransferError("Invalid transfer checkpoint")
        offset, etag = saved.get("offset", 0), saved.get("etag")
        if type(offset) is not int or not 0 <= offset < part.encrypted_part_size:
            offset = 0
        if not path.exists() or path.stat().st_size < offset or not strong_etag(etag):
            offset, etag = 0, None
        if path.exists():
            with path.open("r+b") as output:
                output.truncate(offset)
        for attempt in range(3):
            check_control()
            headers = {"Range": f"bytes={offset}-", "If-Range": str(etag)} if offset else {}
            try:
                with self._stream(part, headers) as response:
                    if response.status_code in {401, 403} and attempt < 2:
                        fresh = self.get_status()
                        if fresh.status.code != 200 or fresh.package is None:
                            raise KsefExportTransferError("Export is no longer available")
                        candidates = {p.ordinal_number: p for p in fresh.package.parts}
                        replacement = candidates.get(part.ordinal_number)
                        if replacement is None or part_identity(replacement) != part_identity(part):
                            raise KsefExportTransferError(
                                "Export part changed while refreshing its URL"
                            )
                        part = replacement
                        continue
                    if response.status_code in {429, 502, 503, 504} and attempt < 2:
                        from .http import _budget_retry_after

                        wait_seconds(_budget_retry_after(response.headers.get("Retry-After")))
                        continue
                    received_etag = response.headers.get("ETag")
                    valid_range = (
                        offset > 0
                        and response.status_code == 206
                        and received_etag == etag
                        and response.headers.get("Content-Range")
                        == (
                            f"bytes {offset}-{part.encrypted_part_size - 1}/"
                            f"{part.encrypted_part_size}"
                        )
                    )
                    if response.status_code == 200:
                        offset = 0
                    elif not valid_range:
                        if response.status_code in {206, 416} and attempt < 2:
                            offset, etag = 0, None
                            continue
                        raise KsefExportTransferError(
                            f"Storage returned HTTP {response.status_code}"
                        )
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise KsefExportTransferError(
                            "Encoded storage response cannot be resumed safely"
                        )
                    header_hash = response.headers.get("x-ms-meta-hash")
                    if (
                        (self.owner.options.require_export_part_hash and header_hash is None)
                        or header_hash is not None
                        and header_hash != part.encrypted_part_hash
                    ):
                        raise KsefExportTransferError(
                            "Storage hash is missing or disagrees with the API"
                        )
                    etag = received_etag if strong_etag(received_etag) else None
                    with path.open("r+b" if path.exists() else "w+b") as output:
                        output.truncate(offset)
                        output.seek(offset)
                        for chunk in response.iter_raw(BUFFER_SIZE):
                            check_control()
                            if offset + len(chunk) > part.encrypted_part_size:
                                raise KsefExportTransferError(
                                    "Storage part exceeds its declared size"
                                )
                            output.write(chunk)
                            output.flush()
                            os.fsync(output.fileno())
                            offset += len(chunk)
                            manifest["progress"][key] = {"offset": offset, "etag": etag}
                            atomic_json(directory / "progress.json", manifest)
                    if digest(path) != expected:
                        raise KsefExportTransferError(
                            "Encrypted export part failed integrity verification"
                        )
                    return
            except httpx.TransportError:
                if attempt == 2:
                    raise KsefExportTransferError(
                        "Storage transfer interrupted; resume with the same state"
                    ) from None
                if not strong_etag(etag):
                    offset = 0

    def download_to(
        self,
        destination: str | Path,
        *,
        work_dir: str | Path,
        timeout: float = 120,
        poll_interval: float = 2,
    ) -> ExportFiles:
        with request_control(timeout_seconds=timeout):
            return self._download_to(
                destination, work_dir=work_dir, timeout=timeout, poll_interval=poll_interval
            )

    def _download_to(
        self,
        destination: str | Path,
        *,
        work_dir: str | Path,
        timeout: float = 120,
        poll_interval: float = 2,
    ) -> ExportFiles:
        status = self.wait(timeout, poll_interval)
        if status.package is None:
            raise KsefExportTransferError("Successful export has no package")
        package = status.package
        parts = package_identity(package)
        target, work = safe_path(Path(destination)), safe_path(Path(work_dir))
        if target.exists() or target == work or target in work.parents or work in target.parents:
            raise KsefExportTransferError(
                "Destination must be new and separate from the working directory"
            )
        work.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.parent.mkdir(parents=True, exist_ok=True)
        identity = {
            "version": 1,
            "environment": self._state.environment,
            "context": hashlib.sha256(self._state.context_key.encode()).hexdigest(),
            "reference": self._state.reference_number,
            "parts": parts,
            "compression": package.compression_type.value,
            "key_fingerprint": hashlib.sha256(self._key + self._iv).hexdigest(),
        }
        with directory_lock(work):
            checkpoint = safe_path(work / "progress.json")
            if checkpoint.exists():
                if checkpoint.stat().st_size > 4 * 1024 * 1024:
                    raise KsefExportTransferError("Transfer checkpoint exceeds size limit")
                manifest = json.loads(checkpoint.read_text(encoding="utf-8"))
                if (
                    type(manifest) is not dict
                    or manifest.get("identity") != identity
                    or type(manifest.get("progress")) is not dict
                ):
                    raise KsefExportTransferError(
                        "Transfer checkpoint belongs to a different export"
                    )
            else:
                manifest = {"identity": identity, "progress": {}}
                atomic_json(checkpoint, manifest)
            for part in sorted(package.parts, key=lambda part: part.ordinal_number):
                self._download_part(part, work, manifest)
            archive = safe_path(work / "archive.bin")
            with archive.open("wb") as output:
                for part in sorted(package.parts, key=lambda part: part.ordinal_number):
                    decrypt_part(
                        work / f"part-{part.ordinal_number}.bin", output, part, self._key, self._iv
                    )
            if archive.stat().st_size != package.size:
                raise KsefExportTransferError("Archive size disagrees with package descriptor")
            with tempfile.TemporaryDirectory(dir=target.parent, prefix=".ksef-export-") as staging:
                stage = Path(staging) / "result"
                stage.mkdir(mode=0o700)
                files = (
                    extract_archive(archive, stage, package.compression_type)
                    if package.parts
                    else ()
                )
                # Atomic directory rename; never replace an existing result directory.
                if target.exists():
                    raise KsefExportTransferError("Destination already exists")
                publish_directory(stage, target)
            metadata = next(
                (target / name for name in files if name.lower() == "_metadata.json"), None
            )
            return ExportFiles(target, files, metadata, package)


def strong_etag(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r'"[\x21\x23-\x7e]+"', value) is not None


def publish_directory(stage: Path, target: Path) -> None:
    # Windows scanners can briefly hold a just-written file open without delete
    # sharing. Retry only that failure, while continuing to refuse replacement.
    for attempt in range(3):
        if target.exists():
            raise KsefExportTransferError("Destination already exists")
        try:
            stage.rename(target)
            return
        except PermissionError:
            if attempt == 2:
                raise
            wait_seconds(0.05 * (attempt + 1))


class AsyncExportOperation(AsyncOperation[m.InvoiceExportStatusResponse]):
    """Async polling with a bounded disk/crypto/HTTP worker for large transfers.

    The worker owns a separate sync transport and never touches the async HTTP
    client. URL refresh is dispatched back onto the owner's event loop.
    Cancellation is propagated and the worker is joined before returning.
    """

    def __init__(self, owner: Any, state: OperationState) -> None:
        ExportOperation(owner, state)  # Validate encryption state before any HTTP.
        self.owner = owner
        super().__init__(
            state, lambda: owner.api.invoices.get_export_status(state.reference_number)
        )

    async def download_to(
        self,
        destination: str | Path,
        *,
        work_dir: str | Path,
        timeout: float = 120,
        poll_interval: float = 2,
    ) -> ExportFiles:
        with request_control(timeout_seconds=timeout):
            return await self._download_to(
                destination, work_dir=work_dir, timeout=timeout, poll_interval=poll_interval
            )

    async def _download_to(
        self,
        destination: str | Path,
        *,
        work_dir: str | Path,
        timeout: float = 120,
        poll_interval: float = 2,
    ) -> ExportFiles:
        from .http import BaseHttpClient

        status = await self.wait(timeout, poll_interval)
        loop = asyncio.get_running_loop()
        cancelled = CancellationToken()

        def refresh(reference: str) -> m.InvoiceExportStatusResponse:
            future = asyncio.run_coroutine_threadsafe(
                self.owner.api.invoices.get_export_status(reference), loop
            )
            try:
                while True:
                    check_control()
                    try:
                        return future.result(timeout=0.05)
                    except concurrent.futures.TimeoutError:
                        if future.done():
                            raise
                        continue
            finally:
                if not future.done():
                    future.cancel()

        def worker() -> ExportFiles:
            # Preserve the configured transport timeout. Cleanup joins this worker;
            # a blocking socket read can finish at its configured inactivity limit.
            options = self.owner.options
            http = BaseHttpClient(options)
            try:
                proxy = SimpleNamespace(
                    options=options,
                    api=SimpleNamespace(
                        http_client=http, invoices=SimpleNamespace(get_export_status=refresh)
                    ),
                )
                operation = ExportOperation(proxy, self.resume_state())
                operation._result, operation._done = status, True
                with request_control(cancellation=cancelled):
                    return operation.download_to(
                        destination, work_dir=work_dir, timeout=timeout, poll_interval=poll_interval
                    )
            finally:
                http.close()

        task = asyncio.create_task(asyncio.to_thread(worker))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled.cancel()
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            with suppress(Exception):
                task.result()
            raise


def decrypt_part(
    path: Path, output: BinaryIO, part: m.InvoicePackagePart, key: bytes, iv: bytes
) -> None:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    sha, size = hashlib.sha256(), 0

    def write(chunk: bytes) -> None:
        nonlocal size
        size += len(chunk)
        if size > part.part_size:
            raise KsefExportTransferError("Decrypted part exceeds declared size")
        sha.update(chunk)
        output.write(chunk)

    try:
        with safe_path(path).open("rb") as source:
            while chunk := source.read(BUFFER_SIZE):
                check_control()
                write(unpadder.update(decryptor.update(chunk)))
        write(unpadder.update(decryptor.finalize()) + unpadder.finalize())
    except ValueError:
        raise KsefExportTransferError("Invalid encrypted part or PKCS7 padding") from None
    if (size, base64.b64encode(sha.digest()).decode()) != (part.part_size, part.part_hash):
        raise KsefExportTransferError("Decrypted export part failed integrity verification")


def extract_archive(archive: Path, target: Path, compression: m.CompressionType) -> tuple[str, ...]:
    files: list[str] = []
    names: set[str] = set()
    total = 0
    compressed_size = max(1, archive.stat().st_size)

    def extract(name: str, declared: int, source: IO[bytes]) -> None:
        nonlocal total
        normalized = _sanitize_archive_entry_name(name, archive_type="export")
        reserved = {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *{f"COM{i}" for i in range(1, 10)},
            *{f"LPT{i}" for i in range(1, 10)},
        }
        collision = normalized.casefold().rstrip(". ")
        if (
            collision in names
            or len(files) >= EXPORT_MAX_ARCHIVE_ENTRIES
            or declared > 500_000_000
            or any(piece.endswith((".", " ")) for piece in normalized.split("/"))
            or any(piece.split(".")[0].upper() in reserved for piece in normalized.split("/"))
        ):
            raise KsefExportTransferError("Unsafe or oversized archive entry")
        names.add(collision)
        path = safe_path(target / normalized)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        size = 0
        with path.open("xb") as output:
            while chunk := source.read(BUFFER_SIZE):
                check_control()
                size += len(chunk)
                total += len(chunk)
                if size > 500_000_000 or total > 2_000_000_000 or total / compressed_size > 200:
                    raise KsefExportTransferError("Archive expansion exceeds safety limits")
                output.write(chunk)
        if size != declared:
            raise KsefExportTransferError("Archive entry has inconsistent size")
        files.append(normalized)

    if compression == m.CompressionType.ZIP:
        with archive.open("rb") as source:
            zip_module: Any = zipfile
            end_record = zip_module._EndRecData(source)
        # Bound central-directory allocation before ZipFile reads it into memory.
        if (
            end_record is None
            or end_record[4] > EXPORT_MAX_ARCHIVE_ENTRIES
            or end_record[5] > 16 * 1024 * 1024
        ):
            raise KsefExportTransferError("ZIP directory exceeds safety limits")
        with zipfile.ZipFile(archive) as zipped:
            for entry in zipped.infolist():
                if entry.filename.endswith("/"):
                    continue
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise KsefExportTransferError("Archive symlinks are not allowed")
                with zipped.open(entry) as zip_source:
                    extract(entry.filename, entry.file_size, zip_source)
    elif compression == m.CompressionType.TARGZ:
        with tarfile.open(archive, mode="r|gz") as tar:
            for tar_entry in tar:
                if tar_entry.isdir():
                    continue
                if not tar_entry.isfile():
                    raise KsefExportTransferError("Only regular archive files are allowed")
                tar_source = tar.extractfile(tar_entry)
                if tar_source is None:
                    raise KsefExportTransferError("Unreadable archive entry")
                with tar_source:
                    extract(tar_entry.name, tar_entry.size, tar_source)
    else:
        raise KsefExportTransferError("Unsupported export compression")
    return tuple(files)
