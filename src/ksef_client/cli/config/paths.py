from __future__ import annotations

import os
from pathlib import Path

APP_DIR_NAME = "ksef-cli"


def config_dir() -> Path:
    appdata = os.getenv("APPDATA")
    if appdata:
        return Path(appdata) / APP_DIR_NAME
    return Path.home() / ".config" / APP_DIR_NAME


def cache_dir() -> Path:
    local_appdata = os.getenv("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / APP_DIR_NAME
    return Path.home() / ".cache" / APP_DIR_NAME


def config_file() -> Path:
    return config_dir() / "config.json"


def cache_file() -> Path:
    return cache_dir() / "cache.json"
