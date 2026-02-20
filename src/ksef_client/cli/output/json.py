from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


class JsonRenderer:
    def __init__(self, *, started_at: datetime | None = None) -> None:
        self._started_at = started_at or datetime.now(timezone.utc)

    def _meta(self) -> dict[str, int]:
        now = datetime.now(timezone.utc)
        duration_ms = int(max(0.0, (now - self._started_at).total_seconds() * 1000))
        return {"duration_ms": duration_ms}

    def info(self, message: str, *, command: str | None = None) -> None:
        payload = {
            "ok": True,
            "command": command or "info",
            "profile": None,
            "data": {"message": message},
            "errors": [],
            "meta": self._meta(),
        }
        print(json.dumps(payload, ensure_ascii=True))

    def success(
        self,
        *,
        command: str,
        profile: str,
        data: dict[str, Any] | None = None,
        message: str | None = None,
    ) -> None:
        payload_data: dict[str, Any] = dict(data or {})
        if message:
            payload_data["message"] = message
        payload = {
            "ok": True,
            "command": command,
            "profile": profile,
            "data": payload_data,
            "errors": [],
            "meta": self._meta(),
        }
        print(json.dumps(payload, ensure_ascii=True))

    def error(
        self,
        *,
        command: str,
        profile: str,
        code: str,
        message: str,
        hint: str | None = None,
    ) -> None:
        error = {"code": code, "message": message}
        if hint:
            error["hint"] = hint
        payload = {
            "ok": False,
            "command": command,
            "profile": profile,
            "data": None,
            "errors": [error],
            "meta": self._meta(),
        }
        print(json.dumps(payload, ensure_ascii=True))
