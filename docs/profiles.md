# Profile klienta (`ksef_client.profiles`)

Profile to nazwane zestawy ustawień połączenia (środowisko, adres API, kontekst), zapisane
w pliku współdzielonym z CLI. Dzięki temu konfiguracja utworzona przez `ksef init` działa
także w kodzie — bez powielania NIP-u i adresów w każdym skrypcie.

Moduł nie wymaga dodatku `cli`: działa po samym `pip install ksef-client`.

## Szybki start

```python
from ksef_client import KsefClient
from ksef_client.profiles import ProfileStore

store = ProfileStore.default()
profile = store.get("demo")
client = KsefClient(profile.to_options())
```

albo krócej:

```python
from ksef_client import KsefClient, KsefClientOptions

client = KsefClient(KsefClientOptions.from_profile("demo"))
```

## Gdzie leży konfiguracja

Ten sam plik co CLI: `config.json` w katalogu `ksef-cli` (na Windows `%APPDATA%\ksef-cli`,
na pozostałych systemach `~/.config/ksef-cli`). Ścieżkę można sprawdzić przez
`ProfileStore.default().path` albo `ksef_client.paths.config_file()`.

Zapis jest **addytywny względem CLI**:

- SDK zachowuje nieznane klucze najwyższego poziomu i nieznane pola profili, więc nie kasuje
  ustawień dodanych przez nowszą wersję CLI;
- plik jest zapisywany atomowo (plik tymczasowy + `os.replace`);
- plik powstaje z uprawnieniami `0600` (best effort — na Windows decyduje ACL);
- każda operacja czyta plik od nowa, więc zmiany z CLI są widoczne natychmiast.

## API

### `ProfileStore(path=None)`

`path=None` oznacza standardową lokalizację. Każda instancja jest lekka — można tworzyć ją
wielokrotnie.

| Metoda | Opis |
| --- | --- |
| `list()` | wszystkie poprawne profile, posortowane po nazwie |
| `active()` / `active_name()` | aktywny profil (albo `None`) |
| `find(name)` | profil albo `None` |
| `get(name)` | profil albo `ProfileError` |
| `create(name, *, base_url=None, env=None, context_type, context_value, activate=False)` | tworzy profil |
| `update(name, *, env=..., base_url=..., context_type=..., context_value=...)` | zmienia wybrane pola |
| `set_active(name)` | ustawia profil aktywny |
| `delete(name)` | usuwa profil |

Pola `env` przyjmują `TEST`, `DEMO` lub `PROD`; jawny `base_url` ma pierwszeństwo przed `env`.
Nazwa profilu musi pasować do `[A-Za-z0-9._-]{1,64}` i nie może zawierać `..` — trafia do
ścieżki katalogu sesji w CLI, więc jest walidowana także w SDK.

### `Profile`

```python
@dataclass(frozen=True)
class Profile:
    name: str
    base_url: str
    context_type: str
    context_value: str
    env: str | None = None
```

- `environment` — środowisko rozpoznane po `base_url` (`KsefEnvironment` albo `None` dla
  własnego adresu/proxy),
- `to_options(**overrides)` — buduje `KsefClientOptions`; jawne nadpisania mają pierwszeństwo.

### `KsefClientOptions.from_profile(profile, *, store=None, **overrides)`

Przyjmuje obiekt `Profile` albo nazwę profilu. `store` domyślnie wskazuje
`ProfileStore.default()`.

```python
options = KsefClientOptions.from_profile("prod", timeout_seconds=15.0)
```

## Obsługa błędów

Wszystkie błędy to `ProfileError` (podklasa `ValueError`) z komunikatem wskazującym przyczynę:

- niepoprawna nazwa lub puste pole kontekstu,
- profil już istnieje / nie istnieje,
- nieobsługiwane środowisko,
- uszkodzony JSON albo plik bez obiektu głównego.

Uszkodzonego pliku SDK **nie nadpisuje** — w przeciwieństwie do CLI, które przenosi go do
kopii `.corrupt-*`. Biblioteka nie powinna po cichu kasować konfiguracji użytkownika; komunikat
podaje ścieżkę pliku do naprawy.

## Zgodność z CLI

`ksef profile create --name demo --env TEST ...` tworzy profil widoczny w SDK, a
`ProfileStore.create(...)` — widoczny w CLI. Spójność ścieżek i formatu pilnuje test
`tests/test_profiles.py` (porównuje `ksef_client.paths` z `ksef_client.cli.config.paths`).
