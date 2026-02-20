from __future__ import annotations

import json
import tempfile
import warnings
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

from ..errors import CliError
from ..exit_codes import ExitCode
from . import paths
from .schema import CliConfig, ProfileConfig

_CONFIG_VERSION = 1


def _corrupt_backup_name(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return path.with_name(f"{path.stem}.corrupt-{timestamp}{path.suffix}")


def _quarantine_corrupt_config(path: Path, *, reason: str) -> None:
    if not path.exists():
        return
    backup_path = _corrupt_backup_name(path)
    try:
        path.replace(backup_path)
    except OSError as exc:
        warnings.warn(
            f"CLI config is invalid ({reason}) and could not be quarantined: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )
        return
    warnings.warn(
        f"CLI config is invalid ({reason}). Original file moved to {backup_path}.",
        RuntimeWarning,
        stacklevel=2,
    )


def _parse_profile(name: str, payload: object) -> ProfileConfig | None:
    if not isinstance(payload, dict):
        return None
    base_url = payload.get("base_url")
    context_type = payload.get("context_type")
    context_value = payload.get("context_value")
    env = payload.get("env")
    if not isinstance(base_url, str):
        return None
    if not isinstance(context_type, str):
        return None
    if not isinstance(context_value, str):
        return None
    if env is not None and not isinstance(env, str):
        return None
    return ProfileConfig(
        name=name,
        env=env,
        base_url=base_url,
        context_type=context_type,
        context_value=context_value,
    )


def load_config() -> CliConfig:
    path = paths.config_file()
    if not path.exists():
        return CliConfig()

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        _quarantine_corrupt_config(path, reason="invalid JSON")
        return CliConfig()
    except OSError:
        return CliConfig()

    if not isinstance(payload, dict):
        _quarantine_corrupt_config(path, reason="invalid root object")
        return CliConfig()

    raw_profiles = payload.get("profiles")
    profiles: dict[str, ProfileConfig] = {}
    if isinstance(raw_profiles, dict):
        for name, raw_profile in raw_profiles.items():
            if not isinstance(name, str):
                continue
            profile = _parse_profile(name, raw_profile)
            if profile is not None:
                profiles[name] = profile

    active_profile = payload.get("active_profile")
    if not isinstance(active_profile, str) or active_profile not in profiles:
        active_profile = None

    return CliConfig(active_profile=active_profile, profiles=profiles)


def save_config(config: CliConfig) -> None:
    path = paths.config_file()
    payload = {
        "version": _CONFIG_VERSION,
        "active_profile": config.active_profile,
        "profiles": {
            name: {
                "env": profile.env,
                "base_url": profile.base_url,
                "context_type": profile.context_type,
                "context_value": profile.context_value,
            }
            for name, profile in config.profiles.items()
        },
    }
    tmp_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, ensure_ascii=True, indent=2)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f"{path.name}.",
            suffix=".tmp",
        ) as tmp_file:
            tmp_file.write(encoded)
            tmp_path = Path(tmp_file.name)
        tmp_path.replace(path)
        tmp_path = None
    except OSError as exc:
        if tmp_path is not None:
            with suppress(OSError):
                tmp_path.unlink(missing_ok=True)
        raise CliError(
            "Cannot save CLI configuration.",
            ExitCode.CONFIG_ERROR,
            f"Check write permissions for {path.parent}.",
        ) from exc
