"""Ścieżki plików konfiguracyjnych SDK.

Moduł celowo **nie importuje** pakietu :mod:`ksef_client.cli`: CLI jest
opcjonalnym dodatkiem (``typer``/``rich``/``keyring``), a SDK musi działać po
samym ``pip install ksef-client``. Nazwa katalogu jest jednak identyczna jak
w CLI, żeby profile zapisane przez ``ksef init`` były widoczne w SDK i
odwrotnie — pilnuje tego test ``tests/test_profiles.py``.

Ścieżki są wyliczane przy każdym wywołaniu, a nie raz przy imporcie, żeby
zmiana ``APPDATA``/``HOME`` w testach i w procesach długo żyjących działała
zgodnie z oczekiwaniem.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Nazwa katalogu aplikacji — wspólna z CLI (``ksef-cli``).
APP_DIR_NAME = "ksef-cli"


def config_dir() -> Path:
    """Katalog konfiguracji użytkownika.

    Na Windows korzysta z ``%APPDATA%``, na pozostałych systemach z
    ``~/.config``. Brak zmiennej środowiskowej nie jest błędem — wtedy
    używany jest katalog domowy.
    """
    appdata = os.getenv("APPDATA")
    if appdata:
        return Path(appdata) / APP_DIR_NAME
    return Path.home() / ".config" / APP_DIR_NAME


def cache_dir() -> Path:
    """Katalog pamięci podręcznej (checkpointy, cache tokenów)."""
    local_appdata = os.getenv("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / APP_DIR_NAME
    return Path.home() / ".cache" / APP_DIR_NAME


def config_file() -> Path:
    """Plik konfiguracji z profilami (JSON, wspólny z CLI)."""
    return config_dir() / "config.json"


def cache_file() -> Path:
    """Plik pamięci podręcznej CLI (tokeny, metadane)."""
    return cache_dir() / "cache.json"


def certificates_dir() -> Path:
    """Katalog magazynu certyfikatów zarządzanego przez SDK."""
    return config_dir() / "certificates"


__all__ = [
    "APP_DIR_NAME",
    "cache_dir",
    "cache_file",
    "certificates_dir",
    "config_dir",
    "config_file",
]
