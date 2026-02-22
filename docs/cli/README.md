# KSeF Python CLI (`ksef`)

Ten dokument opisuje aktualne CLI 1:1 wobec implementacji w `src/ksef_client/cli`.

## Cel

CLI ma skracac droge od instalacji do pierwszej realnej operacji KSeF:
`init -> auth -> invoice/send/upo`.

## Co jest zaimplementowane

- onboarding i profile:
  - `init`
  - `profile list/show/use/create/set/delete`
- auth:
  - `auth login-token`
  - `auth login-xades`
  - `auth status`
  - `auth refresh`
  - `auth logout`
- diagnostyka:
  - `health check`
- faktury i UPO:
  - `invoice list`, `invoice download`
  - `send online`, `send batch`, `send status`
  - `upo get`, `upo wait`
- eksport:
  - `export run`, `export status`
- output:
  - human
  - `--json` (stabilny envelope)

## Szybki start (2-3 minuty)

1. Instalacja:

```bash
pip install -e .
```

2. Inicjalizacja profilu:

```bash
ksef init --non-interactive --name demo --env DEMO --context-type nip --context-value <NIP> --set-active
```

3. Logowanie tokenem + szybka weryfikacja sesji:

```bash
ksef auth login-token
ksef auth status
ksef profile show
```

4. Pierwsze operacje:

```bash
ksef invoice list --from 2026-01-01 --to 2026-01-31
ksef send online --invoice ./fa.xml --wait-upo --save-upo ./out/upo-online.xml
ksef invoice download --ksef-number <KSEF_NUMBER> --out ./out/
```

## Drzewo komend

```text
ksef
  init
  profile
    list
    show
    use
    create
    set
    delete
  auth
    login-token
    login-xades
    status
    refresh
    logout
  health
    check
  invoice
    list
    download
  send
    online
    batch
    status
  upo
    get
    wait
  export
    run
    status
```

## Opcje globalne

```text
Usage: ksef [OPTIONS] COMMAND [ARGS]...

Options:
  --profile TEXT
  --json
  -v, --verbose
  --no-color
  --version
  --help
```

Zachowanie profilu:
- gdy podasz `--profile`, CLI uzywa tej nazwy,
- gdy podasz nieistniejacy `--profile`, CLI zwraca blad walidacji (exit code `2`),
- gdy nie podasz, CLI bierze `active_profile` z configu,
- gdy brak `active_profile`, komendy biznesowe zwracaja blad konfiguracji (exit code `6`).
- gdy nie podasz `--base-url`, CLI bierze kolejno: CLI option -> `KSEF_BASE_URL` -> `profile.base_url` -> DEMO.

Brak aktywnego profilu:
- komendy `auth`, `health`, `invoice`, `send`, `upo`, `export` wymagaja aktywnego profilu,
- jesli profil nie jest ustawiony, CLI zwraca czytelny blad z podpowiedzia:
  - `ksef init --set-active`
  - `ksef profile use --name <name>`
  - albo uruchomienie komendy z `--profile <name>`.
- komendy onboardingu (`init`, `profile ...`) dzialaja bez aktywnego profilu.

Srodowiska i `base_url` (aby uniknac przypadkowego DEMO):
- `ksef init --env DEMO` ustawia `https://api-demo.ksef.mf.gov.pl`,
- `ksef init --env TEST` ustawia `https://api-test.ksef.mf.gov.pl`,
- `ksef init --env PROD` ustawia `https://api.ksef.mf.gov.pl`.
- `--base-url` ma najwyzszy priorytet i nadpisuje `--env`.
- po zmianie profilu/srodowiska uruchom:
  - `ksef profile show`
  - `ksef auth status`

## Komendy onboarding/profile

## `ksef init`

- tryb interaktywny (domyslnie): CLI pyta o brakujace dane,
- tryb nieinteraktywny: `--non-interactive` + komplet danych,
- `--set-active` ustawia profil jako aktywny.

```text
Usage: ksef init [OPTIONS]

Options:
  --name TEXT
  --env TEXT
  --base-url TEXT
  --context-type TEXT
  --context-value TEXT
  --non-interactive
  --set-active
```

## `ksef profile create`

```text
Usage: ksef profile create [OPTIONS]

Options:
  --name TEXT                 [required]
  --env TEXT
  --base-url TEXT
  --context-type TEXT         [default: nip]
  --context-value TEXT        [required]
  --set-active
```

Uwagi:
- podaj `--env` albo `--base-url` (gdy oba puste, fallback to DEMO),
- `profile set --key env --value TEST` automatycznie przestawia tez `base_url`.

## `ksef profile show`

```text
Usage: ksef profile show [OPTIONS]

Options:
  --name TEXT
```

Uwagi:
- bez `--name` komenda bierze aktywny profil,
- gdy brak aktywnego profilu i brak `--name`, CLI zwraca blad konfiguracji (exit code `6`).

## `ksef profile set`

```text
Usage: ksef profile set [OPTIONS]

Options:
  --name TEXT                                 [required]
  --key [env|base_url|context_type|context_value] [required]
  --value TEXT                                [required]
```

## Komendy auth

## `ksef auth login-token`

```text
Usage: ksef auth login-token [OPTIONS]

Options:
  --ksef-token TEXT
  --context-type TEXT
  --context-value TEXT
  --base-url TEXT
  --poll-interval FLOAT     [default: 2.0]
  --max-attempts INTEGER    [default: 90]
  --save/--no-save          [default: save]
```

Zrodlo tokenu:
- `--ksef-token` ma najwyzszy priorytet,
- gdy `--ksef-token` nie jest podany, CLI czyta `KSEF_TOKEN`.
- gdy `--ksef-token` nie jest podany i brak `KSEF_TOKEN`, CLI pyta o token ukrytym promptem (tryb interaktywny).
- podanie sekretu bezposrednio w `--ksef-token <wartosc>` powoduje ostrzezenie runtime (bez ujawniania sekretu).

Fallback kontekstu:
- `context_type` i `context_value` sa brane kolejno z: CLI option -> env (`KSEF_CONTEXT_*`) -> aktywny profil.

## `ksef auth login-xades`

```text
Usage: ksef auth login-xades [OPTIONS]

Options:
  --pkcs12-path TEXT
  --pkcs12-password TEXT
  --cert-pem TEXT
  --key-pem TEXT
  --key-password TEXT
  --context-type TEXT
  --context-value TEXT
  --base-url TEXT
  --subject-identifier-type TEXT [default: certificateSubject]
  --poll-interval FLOAT          [default: 2.0]
  --max-attempts INTEGER         [default: 90]
  --save/--no-save               [default: save]
```

Walidacja:
- uzyj dokladnie jednego zrodla certyfikatu:
  - `--pkcs12-path`, albo
  - para `--cert-pem` + `--key-pem`.
- gdy hasla (`--pkcs12-password`, `--key-password`) nie sa podane, CLI moze zapytac o nie ukrytym promptem (tryb interaktywny; puste wejscie = brak hasla).
- podanie hasla bezposrednio w opcji (`--pkcs12-password <wartosc>`, `--key-password <wartosc>`) powoduje ostrzezenie runtime (bez ujawniania sekretu).

Fallback kontekstu:
- `context_type` i `context_value` sa brane kolejno z: CLI option -> env (`KSEF_CONTEXT_*`) -> aktywny profil.

## `ksef auth refresh`

```text
Usage: ksef auth refresh [OPTIONS]

Options:
  --base-url TEXT
  --save/--no-save          [default: save]
```

Kiedy uzywac:
- gdy access token wygasl, a refresh token jest nadal wazny,
- gdy chcesz odswiezyc token bez ponownego pelnego logowania.

Uwagi:
- komenda wymaga zapisanych tokenow dla wybranego profilu,
- `--save` aktualizuje zapisany access token.

## `ksef auth logout`

```text
Usage: ksef auth logout [OPTIONS]
```

Kiedy uzywac:
- gdy chcesz usunac lokalnie zapisane tokeny dla biezacego profilu,
- przed przelaczeniem konta lub kontekstu autoryzacji.

## `ksef health check`

```text
Usage: ksef health check [OPTIONS]

Options:
  --dry-run
  --check-auth
  --check-certs
  --base-url TEXT
```

## invoice / send / upo / export

## `ksef invoice list`

```text
Usage: ksef invoice list [OPTIONS]

Options:
  --from TEXT
  --to TEXT
  --subject-type TEXT       [default: Subject1]
  --date-type TEXT          [default: Issue]
  --page-size INTEGER       [default: 10]
  --page-offset INTEGER     [default: 0]
  --sort-order [Asc|Desc]   [default: Desc]
  --base-url TEXT
```

## `ksef invoice download`

```text
Usage: ksef invoice download [OPTIONS]

Options:
  --ksef-number TEXT   [required]
  --out TEXT           [required]
  --as TEXT            [default: xml]
  --overwrite
  --base-url TEXT
```

Uwagi:
- `--out` moze wskazywac plik albo katalog,
- sciezka bez rozszerzenia jest traktowana jako plik (np. `./out/invoice`).

## `ksef send online`

```text
Usage: ksef send online [OPTIONS]

Options:
  --invoice TEXT            [required]
  --system-code TEXT        [default: FA (3)]
  --schema-version TEXT     [default: 1-0E]
  --form-value TEXT         [default: FA]
  --upo-v43
  --wait-status
  --wait-upo
  --poll-interval FLOAT     [default: 2.0]
  --max-attempts INTEGER    [default: 60]
  --save-upo TEXT
  --save-upo-overwrite
  --base-url TEXT
```

Uwagi:
- `--save-upo` wymaga `--wait-upo`.
- `--save-upo` bez rozszerzenia jest traktowane jako sciezka pliku.
- `--save-upo-overwrite` pozwala nadpisac istniejacy plik UPO wskazany przez `--save-upo`.

## `ksef send batch`

```text
Usage: ksef send batch [OPTIONS]

Options:
  --zip TEXT
  --dir TEXT
  --system-code TEXT        [default: FA (3)]
  --schema-version TEXT     [default: 1-0E]
  --form-value TEXT         [default: FA]
  --parallelism INTEGER     [default: 4]
  --upo-v43
  --wait-status
  --wait-upo
  --poll-interval FLOAT     [default: 2.0]
  --max-attempts INTEGER    [default: 120]
  --save-upo TEXT
  --save-upo-overwrite
  --base-url TEXT
```

Walidacja:
- dokladnie jedno z `--zip` albo `--dir`.
- `--save-upo-overwrite` pozwala nadpisac istniejacy plik UPO wskazany przez `--save-upo`.

## `ksef upo get`

```text
Usage: ksef upo get [OPTIONS]

Options:
  --session-ref TEXT    [required]
  --invoice-ref TEXT
  --ksef-number TEXT
  --upo-ref TEXT
  --out TEXT            [required]
  --overwrite
  --base-url TEXT
```

Walidacja:
- dokladnie jedno z: `--invoice-ref`, `--ksef-number`, `--upo-ref`.

## `ksef upo wait`

```text
Usage: ksef upo wait [OPTIONS]

Options:
  --session-ref TEXT         [required]
  --invoice-ref TEXT
  --upo-ref TEXT
  --batch-auto
  --poll-interval FLOAT      [default: 2.0]
  --max-attempts INTEGER     [default: 60]
  --out TEXT
  --overwrite
  --base-url TEXT
```

Walidacja:
- dokladnie jeden tryb: `--invoice-ref` albo `--upo-ref` albo `--batch-auto`.

## `ksef export run`

```text
Usage: ksef export run [OPTIONS]

Options:
  --from TEXT
  --to TEXT
  --subject-type TEXT        [default: Subject1]
  --poll-interval FLOAT      [default: 2.0]
  --max-attempts INTEGER     [default: 120]
  --out TEXT                 [required]
  --base-url TEXT
```

## Exit codes

- `0` sukces
- `2` blad walidacji
- `3` blad auth/token
- `4` retry exhausted / rate-limit
- `5` blad API KSeF
- `6` blad konfiguracji/srodowiska
- `7` circuit breaker open
- `8` blad I/O

## Bezpieczenstwo tokenow

- Rekomendacja dla sekretow auth: nie podawaj ich bezposrednio w argumentach CLI.
  - interaktywnie: pomin opcje sekretu i wpisz wartosc w ukrytym prompcie,
  - automatyzacja: uzyj zmiennych srodowiskowych (np. `KSEF_TOKEN`) albo managera sekretow.

- Domyslnie CLI wymaga systemowego keyringu do zapisu tokenow.
- Gdy keyring jest niedostepny, mozliwy jest fallback szyfrowany przez klucz z env:

```bash
KSEF_CLI_TOKEN_STORE_KEY=<TWOJ_KLUCZ>
```

- Plaintext fallback do `tokens.json` pozostaje domyslnie zablokowany i jest tylko trybem awaryjnym.
- Mozesz go jawnie wlaczyc (niezalecane) tylko gdy to konieczne:

```bash
KSEF_CLI_ALLOW_INSECURE_TOKEN_STORE=1
```

- Gdy CLI faktycznie uzyje plaintext fallback, wypisuje jawne ostrzezenie o niezabezpieczonym zapisie tokenow.
- Na Windows plaintext fallback jest zablokowany nawet po ustawieniu tej zmiennej; uzyj keyringa albo fallbacku szyfrowanego.
- Gdy keyring jest obecny, ale backend zwraca blad, CLI automatycznie przechodzi na dostepny fallback (`KSEF_CLI_TOKEN_STORE_KEY` lub awaryjny plaintext poza Windows).
- `ksef health check` oraz diagnostyka preflight pokazuja aktualny tryb polityki token-store jako jedno z:
  - `keyring`
  - `encrypted-fallback`
  - `plaintext-fallback`
  - `unavailable`

Lokalizacja token fallback:
- Windows: `%LOCALAPPDATA%/ksef-cli/tokens.json`
- Linux/macOS: `~/.cache/ksef-cli/tokens.json`

## Odporność configu

- Zapis `config.json` jest atomowy (tmp + rename), aby ograniczyc ryzyko uszkodzenia pliku.
- Gdy `config.json` jest uszkodzony (np. niepoprawny JSON), CLI przenosi go do pliku `config.corrupt-<timestamp>.json` i startuje z pustym configiem.

## Lokalizacje plikow CLI

- Konfiguracja:
  - Windows: `%APPDATA%/ksef-cli/config.json`
  - Linux/macOS: `~/.config/ksef-cli/config.json`
- Cache metadanych:
  - Windows: `%LOCALAPPDATA%/ksef-cli/cache.json`
  - Linux/macOS: `~/.cache/ksef-cli/cache.json`
- Fallback token store:
  - Windows: `%LOCALAPPDATA%/ksef-cli/tokens.json`
  - Linux/macOS: `~/.cache/ksef-cli/tokens.json`
- Kopia uszkodzonego configu:
  - `config.corrupt-<timestamp>.json` w tym samym katalogu co `config.json`.

## JSON contract (`--json`)

```json
{
  "ok": true,
  "command": "invoice.list",
  "profile": "demo",
  "data": {},
  "errors": [],
  "meta": {
    "duration_ms": 120
  }
}
```

Uwagi:
- w zdarzeniach informacyjnych (`command=info`) pole `profile` moze byc `null`,
- w bledzie: `ok=false`, a `errors` zawiera `code`, `message`, opcjonalnie `hint`.
