from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProfileConfig:
    name: str
    env: str | None
    base_url: str
    context_type: str
    context_value: str


@dataclass
class CliConfig:
    active_profile: str | None = None
    profiles: dict[str, ProfileConfig] = field(default_factory=dict)
