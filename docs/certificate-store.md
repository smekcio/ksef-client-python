# Magazyn certyfikatów (`ksef_client.certificates`)

CLI nie przechowuje certyfikatów XAdES — przy każdym logowaniu podaje się ścieżki. Ten moduł
daje SDK odpowiednik magazynu: nazwany zestaw „certyfikat + klucz prywatny” na dysku, z
metadanymi i uprawnieniami `0600`.

Moduł korzysta wyłącznie z `cryptography`, czyli z zależności już wymaganej przez SDK — nie
dodaje nowych pakietów.

## Szybki start

```python
from ksef_client.certificates import FileCertificateStore

store = FileCertificateStore.default()
store.save(
    "prod-2026",
    certificate=Path("cert.pem").read_bytes(),
    private_key=Path("key.pem").read_bytes(),
    environment="PROD",
)

credentials = store.load("prod-2026")
certificate, private_key = credentials.key_pair()
```

Odczytany obiekt można przekazać do istniejącego workflow XAdES:

```python
from ksef_client.services import AuthCoordinator

access_token = AuthCoordinator(client.auth).authenticate_with_xades_key_pair(
    certificate=certificate,
    private_key=private_key,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
).access_token
```

## Układ na dysku

```
<katalog>/<nazwa>/cert.pem    # 0600
<katalog>/<nazwa>/key.pem     # 0600, opcjonalnie zaszyfrowany hasłem
<katalog>/<nazwa>/meta.json   # 0600, metadane wpisu
```

Domyślny katalog to `ksef_client.paths.certificates_dir()`, czyli
`<config_dir>/certificates` (na Windows `%APPDATA%\ksef-cli\certificates`).

`meta.json` jest tylko wygodą (etykieta środowiska, data zapisu) — źródłem prawdy przy odczycie
jest `cert.pem`. Uszkodzone lub brakujące metadane nie blokują `load()`.

## API

### `FileCertificateStore(directory=None)`

| Metoda | Opis |
| --- | --- |
| `save(name, *, certificate, private_key, password=None, environment=None, overwrite=False)` | zapisuje parę; waliduje, że klucz pasuje do certyfikatu |
| `load(name, *, password=None)` | zwraca `StoredCertificate` |
| `record(name)` | metadane bez wczytywania klucza (działa też dla zaszyfrowanych wpisów) |
| `list()` | metadane wszystkich wpisów, posortowane po nazwie |
| `delete(name)` | usuwa wpis |
| `exists(name)` | czy wpis istnieje |

`certificate` i `private_key` przyjmują obiekt `cryptography` albo dane PEM (`bytes`/`str`).
Obsługiwane klucze: **RSA** i **EC** (takie, jakie przyjmuje XAdES w KSeF).

### `StoredCertificate`

```python
@dataclass(frozen=True)
class StoredCertificate:
    record: CertificateRecord
    certificate: x509.Certificate
    private_key: RSAPrivateKey | EllipticCurvePrivateKey
    certificate_pem: bytes
    private_key_pem: bytes
```

### `CertificateRecord`

`name`, `subject` (RFC 4514), `serial_number` (hex), `not_valid_before`, `not_valid_after`,
`fingerprint_sha256`, `environment`, `created_at`, `has_password`.

### Protokół `CertificateStore`

`FileCertificateStore` implementuje `CertificateStore` (`typing.Protocol`, `runtime_checkable`).
Własna implementacja (Vault, KMS, baza) wystarczy, jeśli ma metody `save`, `load`, `list`,
`delete`, `exists`.

## Hasło do klucza

`password` szyfruje klucz prywatny przy zapisie (`PKCS#8` + `BestAvailableEncryption`).
Hasło **nie jest** zapisywane — `load()` bez hasła zgłosi `CertificateStoreError` z prośbą
o jego podanie, a `record()` nadal zadziała (czyta tylko certyfikat).

```python
store.save("prod", certificate=cert, private_key=key, password="sekret")
store.load("prod")                    # CertificateStoreError: podaj hasło
store.load("prod", password="sekret") # OK
```

Jeśli klucze **muszą** być szyfrowane, utwórz magazyn w trybie wymuszającym:

```python
from ksef_client.certificates import FileCertificateStore

store = FileCertificateStore(require_password=True)
store.save("prod", certificate=cert, private_key=key)   # CertificateStoreError
store.save("prod", certificate=cert, private_key=key, password="sekret")  # OK
```

Tryb `require_password=True` jest zalecany dla środowisk produkcyjnych i automatów, w których
klucz nie może leżeć na dysku jawnym tekstem.

## Bezpieczeństwo

- nazwa wpisu jest walidowana (`[A-Za-z0-9._-]{1,64}`, bez `..`, bez kropki na końcu) —
  nie da się wyjść poza katalog ani wskazać `Path(".")` (czyli samego katalogu magazynu),
- pliki powstają atomowo i z uprawnieniami `0600` (na Windows `chmod` nie steruje ACL —
  klucz chroni dziedziczony ACL katalogu użytkownika),
- zapis odrzuca parę, w której klucz nie pasuje do certyfikatu (ochrona przed pomyleniem plików),
- `repr(StoredCertificate)` **nie zawiera klucza** — materiał klucza jest oznaczony jako
  `<redacted>`, więc log obiektu nie wycieka sekretu,
- nieudany `save(overwrite=True)` przywraca poprzednią parę certyfikat + klucz, zamiast
  zostawiać nowy certyfikat ze starym kluczem,
- `delete()` najpierw sprawdza, czy katalog wpisu nie zawiera podkatalogów — nie usuwa
  plików „w połowie”,
- `list()` pokazuje wyłącznie kompletne pary (certyfikat + klucz); wpis bez `key.pem` jest
  pomijany z `RuntimeWarning`, podobnie jak uszkodzony `cert.pem`,
- operacje na wpisie, który jest dowiązaniem symbolicznym, są **odrzucane** (nazwa jest
  walidowana, więc to jedyna droga wyjścia poza magazyn),
- katalogi magazynu powstają z uprawnieniami `0700`, a pliki są zapisywane z `fsync` przed
  `os.replace` (zawartość jest na dysku, zanim podmieni się nazwę).

Domyślnie klucz jest zapisywany **bez hasła** — jeśli nośnik nie jest szyfrowany, podaj
`password`, aby zaszyfrować klucz w PEM (hasło nie jest nigdzie zapisywane).

## Czego moduł nie robi

- nie generuje certyfikatów ani CSR (`ksef_client.services.csr` służy do enrollmentu),
- nie obsługuje PKCS#12 — plik `.p12` trzeba najpierw odczytać przez `load_certificate_and_key_from_p12`
  (jeśli korzystasz z gotowego workflow XAdES, on już to robi),
- nie synchronizuje się z magazynem systemowym (keyring dotyczy tokenów w CLI).
