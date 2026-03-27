# ruff: noqa: F403
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .openapi_models import *

@dataclass(frozen=True)
class FileMetadata:
    file_size: int
    sha256_base64: str


@dataclass(frozen=True)
class InvoiceContent:
    content: str
    sha256_base64: str | None = None


@dataclass(frozen=True)
class BinaryContent:
    content: bytes
    sha256_base64: str | None = None


class LighthouseKsefStatus(str, Enum):
    AVAILABLE = ...
    MAINTENANCE = ...
    FAILURE = ...
    TOTAL_FAILURE = ...


class LighthouseMessageCategory(str, Enum):
    FAILURE = ...
    TOTAL_FAILURE = ...
    MAINTENANCE = ...


class LighthouseMessageType(str, Enum):
    FAILURE_START = ...
    FAILURE_END = ...
    MAINTENANCE_ANNOUNCEMENT = ...


@dataclass(frozen=True)
class LighthouseMessage:
    id: str
    event_id: int
    category: LighthouseMessageCategory
    type: LighthouseMessageType
    title: str
    text: str
    start: str
    end: str | None
    version: int
    published: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> LighthouseMessage: ...

    def to_dict(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class LighthouseStatusResponse:
    status: LighthouseKsefStatus
    messages: list[LighthouseMessage] | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> LighthouseStatusResponse: ...

    def to_dict(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class UnknownApiProblem:
    status: int
    title: str
    detail: str | None = None
    raw: dict[str, Any] | None = None
