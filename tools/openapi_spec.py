from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

# Official KSeF v2 OpenAPI schema endpoint used by local tooling and CI validation.
DEFAULT_KSEF_OPENAPI_URL = "https://api-test.ksef.mf.gov.pl/docs/v2/openapi.json"
# Last successfully synced KSeF OpenAPI snapshot committed to the repository for offline fallback.
DEFAULT_KSEF_OPENAPI_FALLBACK_PATH = (
    Path(__file__).resolve().parents[1] / "specs" / "ksef-openapi.snapshot.json"
)


class OpenApiSpecError(RuntimeError):
    pass


@dataclass(frozen=True)
class OpenApiSpecDocument:
    text: str
    source: str
    used_fallback: bool = False


def fetch_openapi_text(url: str = DEFAULT_KSEF_OPENAPI_URL, *, timeout: float = 30.0) -> str:
    try:
        with urlopen(url, timeout=timeout) as response:
            encoding = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(encoding)
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise OpenApiSpecError(f"Failed to download OpenAPI spec from {url}: {exc}") from exc


def _read_openapi_text_file(input_path: Path) -> str:
    try:
        return input_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OpenApiSpecError(f"Failed to read OpenAPI spec from {input_path}: {exc}") from exc


def write_openapi_snapshot(
    text: str,
    snapshot_path: Path = DEFAULT_KSEF_OPENAPI_FALLBACK_PATH,
) -> None:
    try:
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise OpenApiSpecError(
            f"Failed to write OpenAPI snapshot to {snapshot_path}: {exc}"
        ) from exc


def load_openapi_document(
    input_path: Path | None = None,
    *,
    url: str = DEFAULT_KSEF_OPENAPI_URL,
    timeout: float = 30.0,
    fallback_path: Path = DEFAULT_KSEF_OPENAPI_FALLBACK_PATH,
) -> OpenApiSpecDocument:
    if input_path is not None:
        return OpenApiSpecDocument(text=_read_openapi_text_file(input_path), source=str(input_path))
    try:
        return OpenApiSpecDocument(text=fetch_openapi_text(url=url, timeout=timeout), source=url)
    except OpenApiSpecError as remote_exc:
        try:
            fallback_text = _read_openapi_text_file(fallback_path)
        except OpenApiSpecError as fallback_exc:
            raise OpenApiSpecError(
                f"{remote_exc} Fallback snapshot at {fallback_path} is unavailable: {fallback_exc}"
            ) from remote_exc
        print(
            f"Warning: using fallback OpenAPI snapshot from {fallback_path} because the live spec "
            f"download failed.",
            file=sys.stderr,
        )
        return OpenApiSpecDocument(
            text=fallback_text,
            source=str(fallback_path),
            used_fallback=True,
        )


def load_openapi_text(
    input_path: Path | None = None,
    *,
    url: str = DEFAULT_KSEF_OPENAPI_URL,
    timeout: float = 30.0,
    fallback_path: Path = DEFAULT_KSEF_OPENAPI_FALLBACK_PATH,
) -> str:
    return load_openapi_document(
        input_path=input_path,
        url=url,
        timeout=timeout,
        fallback_path=fallback_path,
    ).text


def parse_openapi_json(document: OpenApiSpecDocument) -> dict[str, Any]:
    try:
        data = json.loads(document.text)
    except json.JSONDecodeError as exc:
        raise OpenApiSpecError(
            f"Failed to decode OpenAPI spec from {document.source}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise OpenApiSpecError(
            f"Expected OpenAPI spec object from {document.source}, got {type(data).__name__}"
        )
    return data


def load_openapi_json(
    input_path: Path | None = None,
    *,
    url: str = DEFAULT_KSEF_OPENAPI_URL,
    timeout: float = 30.0,
    fallback_path: Path = DEFAULT_KSEF_OPENAPI_FALLBACK_PATH,
) -> dict[str, Any]:
    document = load_openapi_document(
        input_path=input_path,
        url=url,
        timeout=timeout,
        fallback_path=fallback_path,
    )
    return parse_openapi_json(document)
