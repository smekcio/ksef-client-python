"""Profile klienta KSeF — wspólne z CLI.

CLI zapisuje profile do ``config.json`` w katalogu ``ksef-cli``. Ten moduł
udostępnia tę samą konfigurację w SDK, bez zależności od opcjonalnego dodatku
``cli`` (``typer``/``rich``/``keyring``):

```python
from ksef_client import KsefClientOptions
from ksef_client.profiles import ProfileStore

store = ProfileStore.default()
profile = store.get("demo")          # profil utworzony przez `ksef init`
client = KsefClient(KsefClientOptions.from_profile(profile))
```

Zapis jest **addytywny względem CLI**: SDK zachowuje nieznane mu klucze
najwyższego poziomu i nieznane pola profili, więc aktualizacja profilu z SDK
nie kasuje ustawień, które doda przyszła wersja CLI. Zapis jest atomowy
(plik tymczasowy + ``os.replace``), a plik powstaje z uprawnieniami ``0600``.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths
from .config import KsefClientOptions, KsefEnvironment

#: Nazwa profilu trafia do ścieżki katalogu sesji w CLI, więc musi być
#: bezpiecznym segmentem: bez separatorów, bez ``..`` i bez znaków spoza ASCII.
_PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

#: Nazwy środowisk akceptowane w polu ``env`` (tak samo jak w CLI).
_ENVIRONMENTS: dict[str, str] = {
    "DEMO": KsefEnvironment.DEMO.value,
    "TEST": KsefEnvironment.TEST.value,
    "PROD": KsefEnvironment.PROD.value,
}

_CONFIG_VERSION = 1

_UNSET: Any = object()


class ProfileError(ValueError):
    """Błąd konfiguracji profili (nazwa, brak profilu, uszkodzony plik)."""


@dataclass(frozen=True)
class Profile:
    """Profil klienta: środowisko, kontekst i bazowy adres API.

    Attributes:
        name: Nazwa profilu (bezpieczny segment ścieżki).
        base_url: Bazowy adres API KSeF.
        context_type: Typ kontekstu uwierzytelnienia (``nip``, ``pesel``...).
        context_value: Wartość kontekstu (np. NIP).
        env: Nazwa środowiska (``TEST``/``DEMO``/``PROD``) albo ``None``.
    """

    name: str
    base_url: str
    context_type: str
    context_value: str
    env: str | None = None

    @property
    def environment(self) -> KsefEnvironment | None:
        """Środowisko KSeF rozpoznane po ``base_url`` (albo ``None``).

        Profil może wskazywać własny ``base_url`` (proxy, środowisko testowe
        wewnątrz firmy), dlatego rozpoznanie opiera się na adresie, a nie na
        polu ``env``.
        """
        base = self.base_url.rstrip("/")
        for environment in KsefEnvironment:
            if base == environment.value or base.startswith(environment.value + "/"):
                return environment
        return None

    def to_options(self, **overrides: Any) -> KsefClientOptions:
        """Buduje :class:`~ksef_client.config.KsefClientOptions` z profilu.

        Args:
            **overrides: Pola nadpisujące wartości z profilu (np.
                ``timeout_seconds=10``). ``base_url`` można nadpisać jawnie.

        Returns:
            Opcje klienta gotowe do przekazania do ``KsefClient``.
        """
        options: dict[str, Any] = {"base_url": self.base_url}
        options.update(overrides)
        return KsefClientOptions(**options)


def normalize_profile_name(name: str) -> str:
    """Waliduje nazwę profilu.

    Args:
        name: Proponowana nazwa.

    Returns:
        Nazwa po usunięciu otaczających białych znaków.

    Raises:
        ProfileError: Gdy nazwa jest pusta, za długa, zawiera ``..`` albo
            znaki spoza ``[A-Za-z0-9._-]``.
    """
    if not isinstance(name, str):
        raise ProfileError(f"Nazwa profilu musi być tekstem, otrzymano {type(name).__name__}.")
    normalized = name.strip()
    if not normalized:
        raise ProfileError("Nazwa profilu nie może być pusta.")
    if not _PROFILE_NAME_RE.fullmatch(normalized) or ".." in normalized:
        raise ProfileError(
            f"Niepoprawna nazwa profilu: {name!r}. "
            "Dozwolone są litery, cyfry, '_', '-' i '.' (bez '..'), np. 'prod' lub 'demo-2'."
        )
    return normalized


def _resolve_base_url(*, env: str | None, base_url: str | None) -> tuple[str, str | None]:
    """Ustala ``base_url`` i nazwę środowiska (jak w CLI)."""
    if base_url is not None and base_url.strip():
        return base_url.strip().rstrip("/"), (env.strip().upper() if env and env.strip() else None)
    if env is None or env.strip() == "":
        return KsefEnvironment.DEMO.value, "DEMO"
    env_name = env.strip().upper()
    if env_name not in _ENVIRONMENTS:
        supported = ", ".join(sorted(_ENVIRONMENTS))
        raise ProfileError(f"Nieobsługiwane środowisko: {env!r}. Dostępne: {supported}.")
    return _ENVIRONMENTS[env_name], env_name


def _require_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProfileError(f"Pole '{field}' musi być niepustym tekstem.")
    return value.strip()


def _parse_profile(name: str, payload: Any) -> Profile | None:
    """Buduje profil z wpisu JSON; ``None`` dla wpisu niezgodnego z formatem."""
    if not isinstance(payload, dict):
        return None
    base_url = payload.get("base_url")
    context_type = payload.get("context_type")
    context_value = payload.get("context_value")
    env = payload.get("env")
    if not isinstance(base_url, str) or not isinstance(context_type, str):
        return None
    if not isinstance(context_value, str):
        return None
    if env is not None and not isinstance(env, str):
        return None
    return Profile(
        name=name,
        base_url=base_url,
        context_type=context_type,
        context_value=context_value,
        env=env,
    )


class ProfileStore:
    """Magazyn profili w pliku JSON współdzielonym z CLI.

    Każda operacja czyta plik na nowo, więc zmiany wykonane przez CLI (albo
    inny proces) są widoczne od razu, bez przeładowywania obiektu. Instancja
    jest lekka i bezpieczna do tworzenia w wielu miejscach.

    Args:
        path: Ścieżka pliku konfiguracji. ``None`` oznacza standardową
            lokalizację (:func:`ksef_client.paths.config_file`).
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else paths.config_file()

    @property
    def path(self) -> Path:
        """Ścieżka pliku konfiguracji używanego przez ten magazyn."""
        return self._path

    @classmethod
    def default(cls) -> ProfileStore:
        """Magazyn w standardowej lokalizacji (tej samej co CLI)."""
        return cls()

    # --- odczyt ---------------------------------------------------------

    def _read_document(self) -> dict[str, Any]:
        if not self._path.exists():
            return {"version": _CONFIG_VERSION, "active_profile": None, "profiles": {}}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProfileError(
                f"Plik profili {self._path} nie jest poprawnym JSON-em: {exc}. "
                "Popraw plik albo usuń go, aby zacząć od zera."
            ) from exc
        except OSError as exc:
            raise ProfileError(f"Nie można odczytać pliku profili {self._path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ProfileError(
                f"Plik profili {self._path} musi zawierać obiekt JSON, "
                f"otrzymano {type(raw).__name__}."
            )
        if not isinstance(raw.get("profiles"), dict):
            raw["profiles"] = {}
        return raw

    def _write_document(self, document: dict[str, Any]) -> None:
        parent = self._path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ProfileError(
                f"Nie można utworzyć katalogu profili {parent}: {exc}."
            ) from exc
        encoded = json.dumps(document, ensure_ascii=True, indent=2)
        temp_path: Path | None = None
        try:
            descriptor, temp_name = tempfile.mkstemp(
                dir=parent,
                prefix=f"{self._path.name}.",
                suffix=".tmp",
            )
            temp_path = Path(temp_name)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(encoded)
            with suppress(OSError):
                os.chmod(temp_path, 0o600)
            os.replace(temp_path, self._path)
            temp_path = None
        except OSError as exc:
            raise ProfileError(
                f"Nie można zapisać pliku profili {self._path}: {exc}. "
                f"Sprawdź uprawnienia do katalogu {parent}."
            ) from exc
        finally:
            if temp_path is not None:
                with suppress(OSError):
                    temp_path.unlink(missing_ok=True)

    def list(self) -> tuple[Profile, ...]:
        """Zwraca wszystkie poprawne profile, posortowane po nazwie."""
        document = self._read_document()
        profiles: list[Profile] = []
        for name, payload in document["profiles"].items():
            if not isinstance(name, str):
                continue
            profile = _parse_profile(name, payload)
            if profile is not None:
                profiles.append(profile)
        return tuple(sorted(profiles, key=lambda profile: profile.name))

    def active_name(self) -> str | None:
        """Nazwa aktywnego profilu albo ``None``.

        Wskaźnik jest zwracany tylko wtedy, gdy wskazuje istniejący profil —
        osierocony wpis (np. po ręcznej edycji pliku) jest traktowany jak brak
        aktywnego profilu, tak samo jak w CLI.
        """
        document = self._read_document()
        active = document.get("active_profile")
        if not isinstance(active, str):
            return None
        payload = document["profiles"].get(active)
        # Wpis musi się jeszcze parsować: sam `dict` nie wystarczy. Wcześniej
        # uszkodzony profil (np. bez `context_value`) dawał `active_name()`
        # różne od `active()`, więc wołający zobaczył nazwę profilu, którego
        # nie dało się użyć.
        if _parse_profile(active, payload) is None:
            return None
        return active

    def active(self) -> Profile | None:
        """Aktywny profil albo ``None``."""
        name = self.active_name()
        if name is None:
            return None
        return _parse_profile(name, self._read_document()["profiles"][name])

    def find(self, name: str) -> Profile | None:
        """Profil o podanej nazwie albo ``None`` (bez wyjątku)."""
        normalized = normalize_profile_name(name)
        document = self._read_document()
        payload = document["profiles"].get(normalized)
        if payload is None:
            return None
        return _parse_profile(normalized, payload)

    def get(self, name: str) -> Profile:
        """Profil o podanej nazwie.

        Raises:
            ProfileError: Gdy profil nie istnieje.
        """
        normalized = normalize_profile_name(name)
        profile = self.find(normalized)
        if profile is None:
            raise ProfileError(
                f"Profil '{normalized}' nie istnieje. "
                "Utwórz go przez `ksef init` albo `ProfileStore.create(...)`."
            )
        return profile

    # --- zapis ----------------------------------------------------------

    def create(
        self,
        name: str,
        *,
        base_url: str | None = None,
        env: str | None = None,
        context_type: str,
        context_value: str,
        activate: bool = False,
    ) -> Profile:
        """Tworzy nowy profil.

        Args:
            name: Nazwa profilu.
            base_url: Jawny adres API; ma pierwszeństwo przed ``env``.
            env: Nazwa środowiska (``TEST``/``DEMO``/``PROD``).
            context_type: Typ kontekstu (np. ``nip``).
            context_value: Wartość kontekstu (np. NIP).
            activate: Czy ustawić nowy profil jako aktywny.

        Returns:
            Utworzony profil.

        Raises:
            ProfileError: Gdy nazwa jest niepoprawna, profil już istnieje albo
                dane są niekompletne.
        """
        normalized = normalize_profile_name(name)
        document = self._read_document()
        profiles = document["profiles"]
        if normalized in profiles:
            raise ProfileError(
                f"Profil '{normalized}' już istnieje. Użyj `update(...)` albo innej nazwy."
            )
        resolved_base_url, resolved_env = _resolve_base_url(env=env, base_url=base_url)
        profile = Profile(
            name=normalized,
            base_url=resolved_base_url,
            context_type=_require_text(context_type, field="context_type"),
            context_value=_require_text(context_value, field="context_value"),
            env=resolved_env,
        )
        profiles[normalized] = {
            "env": profile.env,
            "base_url": profile.base_url,
            "context_type": profile.context_type,
            "context_value": profile.context_value,
        }
        if activate:
            document["active_profile"] = normalized
        document["version"] = _CONFIG_VERSION
        self._write_document(document)
        return profile

    def update(
        self,
        name: str,
        *,
        env: str | None = _UNSET,
        base_url: str | None = _UNSET,
        context_type: str | None = _UNSET,
        context_value: str | None = _UNSET,
    ) -> Profile:
        """Aktualizuje wybrane pola istniejącego profilu.

        Pola pominięte zachowują dotychczasową wartość. Nieznane klucze wpisu
        (dodane przez CLI albo przyszłą wersję SDK) są zachowywane.

        Args:
            name: Nazwa profilu.
            env: Nowe środowisko.
            base_url: Nowy adres API.
            context_type: Nowy typ kontekstu.
            context_value: Nowa wartość kontekstu.

        Returns:
            Zaktualizowany profil.

        Raises:
            ProfileError: Gdy profil nie istnieje albo nowa wartość jest pusta
                lub sprzeczna.
        """
        normalized = normalize_profile_name(name)
        document = self._read_document()
        payload = document["profiles"].get(normalized)
        if not isinstance(payload, dict):
            raise ProfileError(f"Profil '{normalized}' nie istnieje.")
        current = _parse_profile(normalized, payload)
        if current is None:
            raise ProfileError(
                f"Profil '{normalized}' ma niepoprawny format — popraw plik konfiguracji."
            )

        new_env = current.env
        new_base_url = current.base_url
        if base_url is not _UNSET:
            new_base_url, new_env = _resolve_base_url(
                env=new_env if env is _UNSET else env,
                base_url=base_url,
            )
        elif env is not _UNSET:
            new_base_url, new_env = _resolve_base_url(env=env, base_url=None)

        updated = Profile(
            name=normalized,
            base_url=new_base_url,
            context_type=(
                current.context_type
                if context_type is _UNSET
                else _require_text(context_type, field="context_type")
            ),
            context_value=(
                current.context_value
                if context_value is _UNSET
                else _require_text(context_value, field="context_value")
            ),
            env=new_env,
        )
        merged = dict(payload)
        merged.update(
            {
                "env": updated.env,
                "base_url": updated.base_url,
                "context_type": updated.context_type,
                "context_value": updated.context_value,
            }
        )
        document["profiles"][normalized] = merged
        document["version"] = _CONFIG_VERSION
        self._write_document(document)
        return updated

    def set_active(self, name: str) -> Profile:
        """Ustawia profil jako aktywny.

        Raises:
            ProfileError: Gdy profil nie istnieje.
        """
        normalized = normalize_profile_name(name)
        profile = self.get(normalized)
        document = self._read_document()
        document["active_profile"] = normalized
        document["version"] = _CONFIG_VERSION
        self._write_document(document)
        return profile

    def delete(self, name: str) -> None:
        """Usuwa profil.

        Jeśli usunięty profil był aktywny, aktywny staje się pierwszy
        pozostały profil (alfabetycznie) albo ``None``.

        Raises:
            ProfileError: Gdy profil nie istnieje.
        """
        normalized = normalize_profile_name(name)
        document = self._read_document()
        profiles = document["profiles"]
        if normalized not in profiles:
            raise ProfileError(f"Profil '{normalized}' nie istnieje.")
        del profiles[normalized]
        if document.get("active_profile") == normalized:
            remaining = sorted(
                key
                for key, payload in profiles.items()
                if isinstance(key, str) and _parse_profile(key, payload) is not None
            )
            document["active_profile"] = remaining[0] if remaining else None
        document["version"] = _CONFIG_VERSION
        self._write_document(document)


__all__ = [
    "Profile",
    "ProfileError",
    "ProfileStore",
    "normalize_profile_name",
]
