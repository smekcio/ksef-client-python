from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from . import openapi_models as _openapi_models

for _name in dir(_openapi_models):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_openapi_models, _name)


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
    AVAILABLE = "AVAILABLE"
    MAINTENANCE = "MAINTENANCE"
    FAILURE = "FAILURE"
    TOTAL_FAILURE = "TOTAL_FAILURE"


class LighthouseMessageCategory(str, Enum):
    FAILURE = "FAILURE"
    TOTAL_FAILURE = "TOTAL_FAILURE"
    MAINTENANCE = "MAINTENANCE"


class LighthouseMessageType(str, Enum):
    FAILURE_START = "FAILURE_START"
    FAILURE_END = "FAILURE_END"
    MAINTENANCE_ANNOUNCEMENT = "MAINTENANCE_ANNOUNCEMENT"


def _parse_enum(value: Any, enum_type: type[Enum], default: Enum) -> Enum:
    try:
        return enum_type(value)
    except Exception:
        return default


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
    def from_dict(data: dict[str, Any]) -> LighthouseMessage:
        return LighthouseMessage(
            id=str(data.get("id", "")),
            event_id=int(data.get("eventId", 0)),
            category=LighthouseMessageCategory(
                _parse_enum(
                    data.get("category"),
                    LighthouseMessageCategory,
                    LighthouseMessageCategory.FAILURE,
                )
            ),
            type=LighthouseMessageType(
                _parse_enum(
                    data.get("type"),
                    LighthouseMessageType,
                    LighthouseMessageType.FAILURE_START,
                )
            ),
            title=str(data.get("title", "")),
            text=str(data.get("text", "")),
            start=str(data.get("start", "")),
            end=str(data["end"]) if data.get("end") is not None else None,
            version=int(data.get("version", 0)),
            published=str(data.get("published", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "eventId": self.event_id,
            "category": self.category.value,
            "type": self.type.value,
            "title": self.title,
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "version": self.version,
            "published": self.published,
        }


@dataclass(frozen=True)
class LighthouseStatusResponse:
    status: LighthouseKsefStatus
    messages: list[LighthouseMessage] | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> LighthouseStatusResponse:
        raw_messages = data.get("messages")
        messages = (
            [LighthouseMessage.from_dict(item) for item in raw_messages]
            if isinstance(raw_messages, list)
            else None
        )
        return LighthouseStatusResponse(
            status=LighthouseKsefStatus(
                _parse_enum(
                    data.get("status"),
                    LighthouseKsefStatus,
                    LighthouseKsefStatus.AVAILABLE,
                )
            ),
            messages=messages,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": self.status.value}
        if self.messages is not None:
            payload["messages"] = [message.to_dict() for message in self.messages]
        return payload


@dataclass(frozen=True)
class UnknownApiProblem:
    status: int
    title: str
    detail: str | None = None
    raw: dict[str, Any] | None = None


__all__ = [
    *[name for name in dir(_openapi_models) if not name.startswith("_")],
    "BinaryContent",
    "FileMetadata",
    "InvoiceContent",
    "LighthouseKsefStatus",
    "LighthouseMessage",
    "LighthouseMessageCategory",
    "LighthouseMessageType",
    "LighthouseStatusResponse",
    "UnknownApiProblem",
]
