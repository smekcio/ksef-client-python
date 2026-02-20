from __future__ import annotations

from ksef_client.config import KsefEnvironment

from ..constants import DEFAULT_PROFILE
from ..errors import CliError
from ..exit_codes import ExitCode
from .loader import load_config
from .schema import CliConfig, ProfileConfig

_SUPPORTED_ENVS = {
    "DEMO": KsefEnvironment.DEMO.value,
    "TEST": KsefEnvironment.TEST.value,
    "PROD": KsefEnvironment.PROD.value,
}
_EDITABLE_KEYS = {"env", "base_url", "context_type", "context_value"}


def normalize_profile_name(name: str | None) -> str:
    if name is None or name.strip() == "":
        return DEFAULT_PROFILE
    return name.strip()


def resolve_base_url(*, env: str | None, base_url: str | None) -> tuple[str, str | None]:
    if base_url is not None and base_url.strip() != "":
        return base_url.strip(), env.strip().upper() if env and env.strip() else None

    if env is None or env.strip() == "":
        return KsefEnvironment.DEMO.value, "DEMO"

    env_name = env.strip().upper()
    if env_name not in _SUPPORTED_ENVS:
        supported = ", ".join(sorted(_SUPPORTED_ENVS))
        raise CliError(
            f"Unsupported environment: {env}.",
            ExitCode.VALIDATION_ERROR,
            f"Use one of: {supported}.",
        )
    return _SUPPORTED_ENVS[env_name], env_name


def require_profile(config: CliConfig, *, name: str) -> ProfileConfig:
    profile = config.profiles.get(name)
    if profile is None:
        raise CliError(
            f"Profile '{name}' does not exist.",
            ExitCode.CONFIG_ERROR,
            "Create it with `ksef profile create --name ...` or run `ksef init`.",
        )
    return profile


def create_profile(
    config: CliConfig,
    *,
    name: str,
    env: str | None,
    base_url: str | None,
    context_type: str,
    context_value: str,
) -> ProfileConfig:
    if name in config.profiles:
        raise CliError(
            f"Profile '{name}' already exists.",
            ExitCode.VALIDATION_ERROR,
            "Use `ksef profile set ...` or choose another profile name.",
        )
    resolved_base_url, resolved_env = resolve_base_url(env=env, base_url=base_url)
    profile = ProfileConfig(
        name=name,
        env=resolved_env,
        base_url=resolved_base_url,
        context_type=context_type.strip(),
        context_value=context_value.strip(),
    )
    config.profiles[name] = profile
    return profile


def upsert_profile(
    config: CliConfig,
    *,
    name: str,
    env: str | None,
    base_url: str | None,
    context_type: str,
    context_value: str,
) -> tuple[ProfileConfig, bool]:
    existed = name in config.profiles
    resolved_base_url, resolved_env = resolve_base_url(env=env, base_url=base_url)
    profile = ProfileConfig(
        name=name,
        env=resolved_env,
        base_url=resolved_base_url,
        context_type=context_type.strip(),
        context_value=context_value.strip(),
    )
    config.profiles[name] = profile
    return profile, existed


def set_active_profile(config: CliConfig, *, name: str) -> None:
    _ = require_profile(config, name=name)
    config.active_profile = name


def set_profile_value(
    config: CliConfig,
    *,
    name: str,
    key: str,
    value: str,
) -> ProfileConfig:
    profile = require_profile(config, name=name)
    safe_key = key.strip()
    if safe_key not in _EDITABLE_KEYS:
        supported = ", ".join(sorted(_EDITABLE_KEYS))
        raise CliError(
            f"Unsupported profile key: {key}.",
            ExitCode.VALIDATION_ERROR,
            f"Use one of: {supported}.",
        )
    safe_value = value.strip()
    if safe_value == "":
        raise CliError(
            "Profile value cannot be empty.",
            ExitCode.VALIDATION_ERROR,
            "Provide a non-empty value.",
        )
    if safe_key == "env":
        resolved_base_url, resolved_env = resolve_base_url(env=safe_value, base_url=None)
        updated = ProfileConfig(
            name=profile.name,
            env=resolved_env,
            base_url=resolved_base_url,
            context_type=profile.context_type,
            context_value=profile.context_value,
        )
    elif safe_key == "base_url":
        updated = ProfileConfig(
            name=profile.name,
            env=profile.env,
            base_url=safe_value,
            context_type=profile.context_type,
            context_value=profile.context_value,
        )
    elif safe_key == "context_type":
        updated = ProfileConfig(
            name=profile.name,
            env=profile.env,
            base_url=profile.base_url,
            context_type=safe_value,
            context_value=profile.context_value,
        )
    else:
        updated = ProfileConfig(
            name=profile.name,
            env=profile.env,
            base_url=profile.base_url,
            context_type=profile.context_type,
            context_value=safe_value,
        )
    config.profiles[name] = updated
    return updated


def delete_profile(config: CliConfig, *, name: str) -> None:
    _ = require_profile(config, name=name)
    del config.profiles[name]
    if config.active_profile == name:
        config.active_profile = sorted(config.profiles.keys())[0] if config.profiles else None


def get_config() -> CliConfig:
    return load_config()
