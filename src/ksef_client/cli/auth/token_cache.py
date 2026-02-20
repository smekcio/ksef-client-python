from __future__ import annotations

import json
from datetime import datetime, timezone

from ..config.paths import cache_file
from ..errors import CliError
from ..exit_codes import ExitCode


def _load_cache() -> dict[str, dict[str, dict[str, str]]]:
    path = cache_file()
    if not path.exists():
        return {"profiles": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"profiles": {}}
    if not isinstance(payload, dict):
        return {"profiles": {}}
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict):
        return {"profiles": {}}
    return {"profiles": profiles}


def _save_cache(payload: dict[str, dict[str, dict[str, str]]]) -> None:
    path = cache_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    except OSError as exc:
        raise CliError(
            "Cannot persist token metadata cache.",
            ExitCode.CONFIG_ERROR,
            "Grant write access to cache directory or update cache location settings.",
        ) from exc


def get_cached_metadata(profile: str) -> dict[str, str] | None:
    payload = _load_cache()
    profile_data = payload["profiles"].get(profile)
    if not isinstance(profile_data, dict):
        return None
    return {str(k): str(v) for k, v in profile_data.items()}


def set_cached_metadata(profile: str, metadata: dict[str, str]) -> None:
    payload = _load_cache()
    data = dict(metadata)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    payload["profiles"][profile] = data
    _save_cache(payload)


def clear_cached_metadata(profile: str) -> None:
    payload = _load_cache()
    if profile in payload["profiles"]:
        del payload["profiles"][profile]
        _save_cache(payload)
