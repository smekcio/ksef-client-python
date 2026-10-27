# Changelog

## Unreleased

### Range searches and proactive rate budgets

* Added sync/async `search_invoice_metadata_range()` with inclusive UTC windows,
  one restartable checkpoint, boundary deduplication and HWM-aware completion.
* Added process-local shared `RateLimitBudget` with effective server policies,
  global/IP/context accounting, cooperative deadlines and cancellation.
* Each HTTP attempt receives a budget admission; unused admissions are refunded
  before token refresh, and complete server cooldowns are shared across callers.
* Added multi-year SQLite example support and documented distributed-scope limits.

### Security and reliability review

* Strict resumable-search response validation; malformed metadata never implies completion.
* Fixed long-lived open-ended cursors, Issue-date boundaries and UTC-overflow handling.
* Bounded diagnostic traversal and removed credential-bearing transport/body tracebacks.
* Explicit SQLite page transactions in autocommit mode; fail closed on truncated export
  without a continuation date.
* Verified installed SDK bytes against the exact wheel, checked sdist identity,
  scoped CI secrets to required steps and pinned release actions to commit SHAs.
* Raised security floors for cryptography, existing HTTP dependencies and development tools.

### Features

* **sdk:** `search_invoice_metadata()` w sync/async z wersjonowanym kursorem v1,
  kontynuacją po obcięciu, deduplikacją granic i kontrolą HWM. Istniejące iteratory
  zachowują zachowanie. Dodano błędy paginacji i przykład transakcyjnego checkpointu SQLite.
* **security:** rozszerzona redakcja `repr()` tokenów, podpisanych URL-i, nagłówków
  i payloadów oraz `redact_sensitive()` do diagnostyki; serializacja transportowa bez zmian.
* **ci:** publikacja wyłącznie z taga, po obowiązkowym E2E TEST z zainstalowanego
  wheela, kontroli wymaganych scenariuszy JUnit i zgodności sum dystrybucji.

* **sdk:** taksonomia błędów — `KsefError` + `ErrorCode`, `KsefExceptionCode`
  (54 kody `exceptionCode` z KSeF API 2.9.0, w tym `91xx` podpisu XAdES), `ForbiddenReason` oraz podklasy HTTP
  dla walidacji, uwierzytelnienia, uprawnień, sesji, eksportu, certyfikatów i faktur.
  `KsefApiError.exception_codes`/`details`/`reason_code`/`trace_id` i `to_dict()` dają
  stabilny kontrakt dla CLI i MCP; mapowanie jest addytywne, a 429 pozostaje
  `KsefRateLimitError`
* **sdk:** taksonomia błędów dokumentów — `KsefDocumentError` + `KsefDocumentValidationError`,
  `KsefRenderingError`, `KsefVerificationError`, `KsefCheckpointError`. `FA3ParseError`,
  `FA3XmlValidationError` i `Fa3CurrencyMismatchError` są teraz podklasami bazy, więc
  `except ValueError` i dotychczasowe `except FA3ParseError` zachowują zgodność, a nowe
  kody (`document_validation_failed`, `verification_failed`, …) trafiają do CLI/MCP
* **sdk:** klient uwierzytelniony z auto-refresh tokena — `AuthenticatedClient`/
  `AsyncAuthenticatedClient` i `TokenManager`/`AsyncTokenManager`. Token dostępowy jest
  wstrzykiwany w warstwie HTTP, odświeżany proaktywnie 60 s przed wygaśnięciem (`refresh_margin_seconds`)
  i jednorazowo po odpowiedzi 401; refresh jest deduplikowany lockiem, a `on_refresh` pozwala
  zapisać nowy token. `access_token` nie jest już wymagany w żadnej metodzie klientów — jawne
  przekazanie tokena nadal działa i ma pierwszeństwo
* **sdk:** retry HTTP włączany przez `KsefClientOptions(retry=RetryConfig())` — ponawianie
  429/502/503/504 z backoffem wykładniczym i jitterem, respektowanie `Retry-After` (sufit 300 s)
  oraz allowlista metod (`GET`/`PUT`/`DELETE`; `POST` tylko po jawnym dodaniu ścieżki). Retry jest
  domyślnie wyłączony, więc dotychczasowe zachowanie pozostaje bez zmian
* **sdk:** odczyt FA(3) — nowy moduł `ksef_client.documents.fa3.parse` z `parse_invoice_xml()`
  i `FA3Invoice.from_xml()` zamienia dokument FA(3) na model domenowy. Parser pokrywa wszystkie
  rodzaje faktur, adnotacje, zaliczki, korekty, rozliczenie, płatność, warunki transakcji,
  zamówienie, stopkę i załącznik; elementy spoza modelu trafiają do `warnings` (nigdy po cichu),
  a dokumenty z `DOCTYPE`/`ENTITY` są odrzucane. Stawka VAT zaliczki jest wnioskowana
  z podsumowania, a gdy to niemożliwe — jawnie ostrzega i przyjmuje 23% (jak builder). Roundtrip
  `parse → to_xml` jest testowany dla wszystkich rodzajów faktur
* **sdk:** paginacja metadanych faktur — `iter_invoice_metadata_pages()`, `iter_invoice_metadata()`
  i `iter_invoice_metadata_by_date_range()` w `InvoicesClient` i `AsyncInvoicesClient`. Iteratory
  respektują `hasMore`, kończą pracę na limicie 10 000 wyników (`isTruncated`) i na pustej stronie
  z `hasMore=true`, emitując `KsefPaginationWarning`. Nowy moduł `ksef_client.pagination` zawiera
  walidację `pageSize` (10–250) i `pageOffset` oraz stałe kontraktu
* **sdk:** profile klienta i magazyn certyfikatów dostępne bez CLI. `ksef_client.profiles`
  (`ProfileStore`, `Profile`) czyta i zapisuje ten sam `config.json` co `ksef` (z zachowaniem
  nieznanych kluczy i atomowym zapisem `0600`), a `KsefClientOptions.from_profile()` buduje opcje
  z profilu. `ksef_client.certificates` (`FileCertificateStore`) przechowuje parę certyfikat + klucz
  jako PEM, waliduje dopasowanie klucza do certyfikatu i obsługuje klucze szyfrowane hasłem
* **docs:** nowe strony `docs/profiles.md`, `docs/certificate-store.md`, `docs/fa3-parsing.md`
  oraz sekcja paginacji w `docs/api/invoices.md`
* **api:** align with KSeF API 2.9.0 — the OpenAPI snapshot, generated models and the documented
  compatibility level move from 2.8.1 to 2.9.0. New surface: `OwnerPermissionScope` and the optional
  `ownerPermissions` field in the response of `POST /permissions/query/personal/grants` (owner
  permissions of the context). The documented error `21001` („Nieczytelna treść”) now has a CLI hint.
  No endpoints were added, removed or renamed, so nothing else changes for existing integrations
* **test:** a contract-limits guard (`tests/test_api_contract_limits.py`) compares the SDK constants
  and CLI option bounds with `specs/ksef-openapi.snapshot.json`: `pageSize` minima and per-endpoint
  maxima, `min/max` invoices in a collective identifier, identifiers per invoice and per query,
  description length, batch part count and size, and the 100-day query range
* **utils:** add `ksef_client.utils.datetime_parsing` — one place that parses the timestamps the KSeF
  API returns (`2025-10-11T12:23:56.0154302+00:00`), normalising any fractional part to exactly 6
  digits. `datetime.fromisoformat` on Python 3.10 accepts only 3 or 6 digits, so every 7-digit
  timestamp used to be unparseable on the lowest supported interpreter
* **fa3:** honour the schema's `fixed` values and ancestor-scoped requirements —
  `Podmiot1/PrefiksPodatnika` is fixed to `PL`, and `DaneIdentyfikacyjne/Nazwa` is required only
  under `Podmiot1`/`Podmiot1K`/`PodmiotUpowazniony`, not under `Podmiot2`/`Podmiot3`
* **fa3:** the simplified invoice (`SimplifiedInvoiceBuilder`) can now emit a buyer identified by NIP
  alone (`Podmiot2` without `Nazwa`/`Adres`), matching the official `FA_3_Przykład_15.xml`/`_16.xml`
* **fa3:** add `ksef_client.documents.fa3.validation` — schema-constraint validation of the generated
  XML (field lengths, decimal precision, value dictionaries, patterns, date ranges, element
  cardinality and required elements). It runs inside `to_xml()` independently of the business
  `validate` flag, needs no `lxml`, and reports the element path instead of a raw `SCHEMAV_*` error.
  `to_xml(facets=False)` disables it explicitly.
* **api:** align with KSeF API 2.7.1 (IZ invoices POST, generate min 2, query/export 100 days UTC, export compressionType from package)
* **api:** align with KSeF API 2.7.0 (collective identifiers, testdata certificate update)
* **api:** add collective identifier helpers, pagination iterators and CLI `ksef iz`
* **api:** validate collective identifier, KSeF number and certificate serial path parameters
* **api:** refresh KSeF API 2.6.1 OpenAPI snapshot and documentation links
* **api:** support KSeF API 2.6.0 OpenAPI, TarGz exports and system warning headers
* **cli:** add TarGz batch input and export compression options

### Bug Fixes

* **pagination:** `pageOffset` is a **page number**, not a record offset. The iterators and
  `ksef invoice list` incremented it by `page_size`, so with the default `pageSize` they requested
  pages 0, 100, 200... and silently skipped 99 pages of results between them; now the next page is
  always the previous number + 1. `--page-offset` in the merged (all subject types) CLI listing is
  a page number too, consistently with the single-subject-type request
* **certificates:** names equal to `.` or ending with a dot are rejected. `Path(".")` pointed at
  the store directory itself — `delete(".")` removed the store's files and the directory, and
  `save(".", ...)` wrote the key into its root. A corrupt `meta.json` (invalid JSON or non-UTF-8
  bytes) no longer escapes as `UnicodeDecodeError` from `list()`/`record()`/`load()`; metadata is
  optional and falls back to defaults. Passing a password for an unencrypted key now says the key
  is *not* encrypted instead of claiming it is
* **profiles:** profile names `.` and names with a trailing dot are rejected (the name is a
  directory under `sessions/`), and `active()` reads the configuration once, so a profile deleted
  by the CLI between two reads can no longer surface as `KeyError`
* **fa3:** an advance payment whose amount lands in the `P_13_5` basket (procedure XII) used to
  crash the parser with `KeyError`; it now warns and falls back to 23% like other ambiguous cases.
  A `str` document whose XML declaration still says e.g. `encoding="windows-1250"` is no longer
  decoded twice (mojibake); `xs:date` values carrying a timezone (`2026-03-01Z`) are accepted, and
  the number of collected warnings is capped (`MAX_PARSE_WARNINGS`) so a document with millions of
  unknown elements cannot exhaust memory
* **security:** FA(3) elements are matched by their full namespace-qualified tag. A document
  with `<P_2 xmlns="urn:evil">` no longer supplies a value just because the local name matches;
  unknown foreign elements are reported in `invoice.warnings`
* **security:** parser error messages show a sanitized preview of untrusted values (control
  characters become `?`, length is capped), so logging an exception cannot inject terminal
  sequences into logs
* **certificates:** `FileCertificateStore(require_password=True)` refuses to store a plaintext
  key; symlinked entries are rejected by `save/load/delete/record`, `exists()` reports them as
  absent and `list()` skips them; `list()` no longer shows entries without `key.pem`; store
  directories are created with `0700` and file contents are `fsync`-ed before `os.replace`
* **profiles:** writes detect a concurrent modification (SHA-256 of the file captured at read
  time) and raise `ProfileError` instead of silently overwriting another process's change;
  `update(env=None)` clears the environment label without replacing the URL with DEMO;
  the config directory is created with `0700` and the file is `fsync`-ed before replacement
* **fa3:** an order line without `P_12Z`/`P_12Z_XII` keeps `tax=None` instead of silently
  defaulting to 23% — the schema marks the element optional, so the parser must not invent a
  tax rate
* **security:** the FA(3) parser blocks DTD in every encoding. The old byte-level
  guard looked for `<!DOCTYPE`/`<!ENTITY`, so a document encoded as UTF-16 slipped
  past it and `ElementTree` expanded internal entities — an attacker could inflate
  the file ("billion laughs") or inject content into parsed fields. The check now
  parses the document with `expat`, which detects encoding itself and aborts on the
  first DTD declaration, before any entity is expanded. A comment containing the
  literal text `<!DOCTYPE` no longer triggers a false positive
* **security:** `StoredCertificate.__repr__` no longer prints the private key.
  The dataclass default included `private_key_pem` in full, so logging the object
  or an exception holding it leaked the key. The representation now shows
  `<redacted>` for key material, matching the SDK rule that secrets stay out of
  `repr`
* **fa3:** the parser rejects exponent notation (`1e5`) in decimal fields. `Decimal`
  accepts it, but XSD `decimal` does not, and a value such as `1e999999999` could
  later raise `decimal.Overflow` inside advance-payment arithmetic instead of a
  clear parse error
* **fa3:** `Podmiot3/RolaInna` without `OpisRoli` is rejected while parsing. The
  schema requires both, and the old parser produced an invoice that could not be
  serialized again
* **profiles:** `active_name()` validates the profile payload instead of only
  checking that it is a dict — a corrupted active profile no longer yields a name
  that `active()` cannot resolve
* **profiles:** deleting the active profile promotes the first *valid* remaining
  profile; an invalid entry is no longer selected as active
* **certificates:** a failed `save(overwrite=True)` restores the previous
  certificate, key and metadata instead of leaving a mixed pair, and `delete()`
  checks for subdirectories before removing any file
* **security:** `-v/--verbose` no longer leaks pre-signed URL signatures. `logging.basicConfig`
  raises the root level, so the `httpx` logger printed the full request URL (the signature lives in
  the query string) and `httpcore` could print response headers — the HTTP layer's own redaction was
  bypassed. Third-party loggers (`httpx`, `httpcore`, `urllib3`, `keyring`) are clamped to `WARNING`
* **security:** the diagnostic URL no longer carries credentials (`https://user:password@host/...`
  was logged verbatim) and pre-signed validation rejects ambiguous numeric hosts (`2130706433`,
  `0x7f000001`, `127.1`, `0177.0.0.1`) that system resolvers read as IPs, plus IPv4-mapped IPv6
  loopback (`[::ffff:127.0.0.1]`), which slipped past the always-on loopback rule
* **security:** checkpoint and fallback-token files are created with `0600` from the start
  (`open("w")` gave `0644` under the usual umask and the `chmod` ran only after `os.replace`, so a
  crash in that window left a readable file holding the session key or tokens)
* **security:** the FA(3) facet engine applies `xsd:whiteSpace` with XML semantics — `collapse` no
  longer treats NBSP/U+3000/U+0085/… as whitespace. A 600-character NBSP name passed the facets and
  `to_xml()` while the XSD (and KSeF) rejected it; the same hole covered `KodWaluty` lookups
* **security:** `tools/generate_openapi_models.py` escapes every string interpolated into the
  generated module and validates schema/property/alias names as Python identifiers, so a crafted
  OpenAPI document can no longer inject code that runs on `import ksef_client`
* **security:** the XSD resolver fails closed — an unknown `schemaLocation` name raises instead of
  returning `None`, which let `lxml` fetch the resource over the network (`no_network` does not
  cover `xsd:include`)
* **security:** private keys and tokens stay out of `repr()` — `TokenInfo.token`, the generated
  `access_token`/`refresh_token` fields, `XadesKeyPair.private_key_pem`, `EncryptionData.key` and
  the session state's `symmetric_key_base64`
* **http:** SDK exceptions can be pickled and copied again (`KsefApiError.__init__() missing 2
  required positional arguments` broke `ProcessPoolExecutor`/`multiprocessing` error transport),
  `Retry-After` is honoured for 502/503/504 (the CLI retried after 0.25 s instead of the requested
  30 s), network errors and timeouts are wrapped in `KsefHttpError` (original in `__cause__`)
  instead of leaking raw `httpx` exceptions, `skip_auth` strips `Authorization` coming from
  `custom_headers`, and a 429 fills `exception_response` like other statuses do
* **clients:** a non-JSON body on the XAdES init endpoint is reported as `KsefHttpError` with the
  path and `Content-Type` (the fix for the JSON endpoints missed this hand-written `json.loads`)
* **utils:** `fast_extract_ksef_metadata` no longer degrades to O(n²) (a 1.2 MB document with
  64 000 `<NIP>` took 30 s; now 0.1 s) and archive unpacking reads entries in chunks with its own
  byte budget — a 220-byte zip bomb that declared 1 KB used to materialise 256 MB before the limit
  kicked in
* **utils:** archive entry names with control characters (including NUL in a tar PAX `path`) are
  rejected with a clear error instead of failing later on `stat`, and the verification-link hash must
  decode to exactly 32 bytes — an empty or 1-byte value produced a link with no hash at all
* **fa3:** `decimal.InvalidOperation` no longer escapes the public API (`1E+26`, `NaN`, `Infinity`
  raise a readable validation error), deeply nested documents no longer hit `RecursionError` in the
  facet engine or the XSD audit, and `Ilosc`/`NrWiersza*` enforce the `xsd:integer` lexical space
  (`30.0` is reported instead of producing a document the XSD rejects, while `007`/`+1` stop being
  false positives)
* **fa3:** a settlement invoice in a foreign currency scales the mirrored VAT (`P_14_xW`) with the
  same proportion as the PLN buckets — it used to stay at the full order value while `P_14_x` was
  scaled, so the two fields contradicted each other in one document
* **fa3:** the draft path derives `P_15` from the settlement amount for `ROZ`/`KOR_ROZ` (the draft
  emitted `P_15` = full gross with `DoZaplaty` = the amount still to pay, breaking rule ROZ-15 while
  the typed path was consistent), and reports a mismatch for kinds that do not scale
* **fa3:** correction fields (`PrzyczynaKorekty`, `DaneFaKorygowanej`, `P_15ZK`, `NrFaKorygowany`)
  are emitted from the data instead of being silently dropped for `RodzajFaktury != KOR*`; fields
  the schema cannot carry next to the current data are reported as a validation error instead of
  disappearing
* **cli:** one malformed checkpoint no longer breaks `session list` (`"form_code": {}` raised
  `TypeError` and the whole command exited 6) — it lands in `unreadable` with a warning; `auth
  logout` fails loudly when the keyring raises on both delete *and* verify; `export run` reports IO
  problems as `IO_ERROR` instead of `UNEXPECTED`, refuses to overwrite without the new `--overwrite`,
  detects case-insensitive name collisions, keeps `_metadata.json` byte-for-byte and reports
  `is_truncated`/`permanent_storage_hwm_date` with a warning; async `open_upload_and_close` honours
  `parallelism`
* **models:** an unknown or missing Lighthouse status maps to the new `LighthouseKsefStatus.UNKNOWN`
  instead of `AVAILABLE` (a fail-open default reported a broken API as healthy)
* **packaging:** the sdist carries the source tree again (specs, tools, docs and `requirements*.txt`
  — 189 of 306 files were missing), `THIRD_PARTY_NOTICES.md` ships with the license files in the
  wheel and the sdist, the FA(3) schema README is packaged, and the API-version test reads the
  expected version from `README.md` instead of a hard-coded literal that blocked a spec sync
* **test:** the dependency guards catch an unconditional optional import in the core
  (`import lxml.etree` in `config.py` passed both guards while `import ksef_client` failed), and the
  `clients/invoices.py` timestamp-offset normalisation has an assertion that fails when the fix is
  reverted
* **services:** the session state (`OnlineSessionState`, `BatchSessionState`) keeps the AES key out
  of `repr()`. The object ends up in logs and error messages, and `repr()` printed
  `symmetric_key_base64` in full; the IV stays visible (it is not a secret) and serialisation
  (`to_dict`/`to_json`) still carries both fields
* **cli:** HTML pages are rejected in the shapes a captive portal actually produces — not only
  `<!DOCTYPE html>`/`<html>` at the very start, but also after a leading comment, an `<?xml`
  declaration (XHTML), or when the page starts with `head`/`meta`/`script`/`body`/`title`. Six of
  the sampled portal shapes used to be saved as `upo-*.xml` and reported as success
* **cli:** a failed file write is reported as `IO_ERROR` (exit 8) instead of `UNEXPECTED` (exit 6) —
  the `mkdir` guard covered only the directory, so e.g. a too-long file name still escaped as a raw
  `OSError`
* **test:** `requirements-dev.txt` declares `qrcode[pil]` and `pillow`, so the QR tests (which cover
  `services/qr.py` for the 100% gate) actually run in the configuration CI installs; one of them was
  not guarded at all and failed without the `qr` extras
* **packaging:** the sdist check requires the package modules (`src/ksef_client/__init__.py`,
  `models.py`) instead of any path under `src/ksef_client/` — an archive with only the XSD files
  used to pass
* **cli:** `session show` redacts the session key and IV (`symmetric_key_base64`, `iv_base64`)
  by default — the full checkpoint used to be printed to stdout, including JSON mode, so key
  material ended up in terminals, CI logs and screenshots. `--show-secrets` returns the full
  record for a caller that needs it
* **cli:** `health check` exits with code `5` (`API_ERROR`) and `ok: false` when `overall` is
  `FAIL`, instead of reporting success with exit code `0` (a `--dry-run` without the required
  certificates looked like a healthy environment). `WARN` still exits with `0`, and the error
  message lists the failing checks
* **cli:** `ksef lighthouse` reports an unknown profile `base_url` as `CONFIG_ERROR` instead of
  silently showing the TEST environment's statuses. `--base-url`/`KSEF_LIGHTHOUSE_BASE_URL` still
  takes precedence over the profile, and the DEMO→TEST mapping is unchanged
* **cli:** default output file names built from API identifiers are sanitised. A crafted
  `ksefNumber`/reference such as `..\..\escaped` used to write the file outside `--out` (the
  identifier became a path); characters outside `[A-Za-z0-9._-]` are replaced and `.`/`..` fall back
  to `_`, centrally for all eight call sites
* **cli:** a 200 response carrying an HTML page (proxy, captive portal) is rejected before it is
  written, instead of being saved as `upo-*.xml` and reported as success — this covered
  `upo get`/`upo wait`/`session online send`/`batch close` and `invoice download --as bytes`
* **services:** the session state validates the key and IV length (32 B AES-256 key, 16 B IV) with
  a message naming the field. A truncated key used to pass state validation and fail later inside
  `cryptography`; `from_dict`/`from_json`/`load_checkpoint` inherit the check
* **services:** `XadesKeyPair` and `EncryptionData` keep the private key out of `repr()` — printing
  the objects leaked key material into logs. The IV stays visible (it is not a secret)
* **services:** `add_label_to_qr` honours `font_size` (it always used the default bitmap font) and
  never clips the label: the font shrinks down to 6 px, and if the text is still wider than the code
  the canvas grows by exactly the text width and the QR code is centred. Pillow < 10.1 (no `size`
  parameter) falls back to `truetype` and then to the bitmap default
* **services:** `get_stream_metadata` refuses a non-seekable stream unless it reports position 0.
  It used to hash only the remaining bytes while claiming to describe the whole stream — the size
  and hash were silently wrong
* **fa3:** the payment link (`LinkDoPlatnosci`) is checked by the facet table, not only by
  `FA3Invoice.validate()` — a document with a hand-placed link passed `validate_xml_facets()` and
  was rejected by the XSD only. The pattern comes from a single source (`PAYMENT_LINK_PATTERN`)
* **fa3:** `new_transport_intra_eu=True` without `new_transport=True` is reported as an error
  instead of being dropped: `P_42_5` is only emitted together with `P_22=1`, so the document declared
  `P_22N=1` and lost the intra-EU marker without a word
* **fa3:** `FA3BatchDraft.to_json` creates the target directory (like `to_xml_zip` already did), so
  the documented example in `docs/fa3-sdk.md` runs as written instead of raising `FileNotFoundError`
* **fa3:** `xsd_audit` derives what the serializer emits from the emission sites in `xml.py`
  (AST) instead of matching path prefixes, and derives the handler from the code:
  `WarunkiTransakcji` no longer reports `_domain_invoice` (248/402 paths) and the tag set is
  exactly the 288 element names of the schema. The status distribution itself is unchanged
  (`partially_supported` = "the serializer can emit it, no test evidence") — that is a
  measurement of the SDK's completeness, not a defect; what changed is that a dropped emission
  now shows up as `UNSUPPORTED` in the report
* **test:** the Lighthouse OpenAPI coverage test actually runs (it looked for an external checkout
  and always skipped); the contract used by the client is pinned in the test with a negative control
  for drift, while a full external spec still takes precedence
* **test:** `requirements-dev.txt` declares `tomli` for Python < 3.11, so the dependency
  declaration guards stop being silently skipped on the lowest supported interpreter
* **cli:** `-v/--verbose` finally does something. The flag was collected into the CLI context and
  ignored — there was not a single `logger.*` call in `src/`. `-v` sets INFO and `-vv` DEBUG for
  `ksef_client`, and the HTTP layer logs every request (`HTTP GET https://host/v2/invoices -> 200`)
  without the query string, because a pre-signed URL carries its signature there
* **cli:** `session list` no longer hides unreadable checkpoints. A directory with three JSON files
  used to report `count: 1` without a word; the response now carries `unreadable` and `warning`, and
  `list_checkpoints(include_broken=True)` reports an error instead of skipping the file
* **cli:** a failing `mkdir` while writing a checkpoint, a UPO or an invoice is reported as
  `CONFIG_ERROR`/`IO_ERROR` instead of escaping as a raw `OSError`, which the CLI answered with
  `UNEXPECTED` and exit code 6
* **cli:** `auth logout` clears the cached token metadata even when the token store refuses to
  remove the tokens (`finally`) — the stale cache entry made the profile look like an active session
* **services:** `resize_png` keeps a QR code two-tone (`Image.Resampling.NEAREST`). The default
  BICUBIC filter produced 253 grey levels instead of 2 and for 16 of the swept sizes the code
  stopped decoding; a non-positive target size is now a `ValueError` instead of a Pillow exception
* **fa3:** `FA3Draft.validate()` reports the same schema constraints as `to_xml()`. It used to stay
  silent (e.g. for a 3-character NIP) while serialisation raised `FA3XmlValidationError`; the new
  `draft_facet_issues()` shares the tree building with `draft_to_xml`, and serialiser errors land in
  the report instead of being raised
* **fa3:** `KodWaluty`/`WalutaUmowna` are upper-cased before serialisation — `eur` passed the
  case-insensitive dictionary check, but the schema's enumeration is case-sensitive, so only KSeF
  rejected the document
* **fa3:** the facet engine enforces the declared `date_format` (`20260401` and
  `2026-04-01 08:30:00` used to pass the type check because the shared API parser is tolerant), and
  `TDataCzas` accepts an optional timezone offset as the schema allows
* **fa3:** `NewTransportMeans.value`/`tax_amount`/`taxable_base` are reported as warnings — the
  schema has no amount element in `NowySrodekTransportu`, so the values disappeared without a word
* **http:** `Retry-After` is clamped to `0..300 s` (one constant shared by the SDK and the CLI retry
  policy). A server-supplied `Retry-After: 31536000` set `retry_after` to a year and `ksef export`
  summed 730 days of pauses; negative values produced a negative wait. `retry_after_raw` still
  carries the raw header for a caller with its own policy
* **http:** a request with both `json` and `data` raises `ValueError` before anything is sent.
  `httpx` silently picked one of them (`content`) while `Content-Type` announced JSON, so the caller
  could not tell what reached KSeF
* **clients:** a non-JSON body on a JSON endpoint (200 + HTML from a proxy or captive portal) is
  reported as `KsefHttpError` with the path, `Content-Type` and a body preview, instead of a bare
  `json.JSONDecodeError` with no context
* **models:** `Any` stays in the `ksef_client.models` namespace so `typing.get_type_hints()` can
  resolve the string annotations — `StatusInfo` and `UnknownApiProblem` raised
  `NameError: name 'Any' is not defined`, which broke introspection (`openapi_models` kept `Any`
  all along)
* **openapi:** `list_invoices()`/`iter_invoices()` accept a response without
  `collectiveIdentifierNumber`. The contract's own example for `POST /collective-identifiers/invoices`
  omits the field although the schema marks it required, so the generated model raised
  `TypeError: missing 1 required positional argument`
* **packaging:** the sdist no longer ships tests that cannot run from it (`MANIFEST.in` prunes
  `tests/`; unpacking the archive used to end with `12 errors during collection`). The documented
  build tool now verifies the artefacts instead of just the wheel's stubs: four XSD files in the
  wheel, `to_xml(xsd_validate=True)` from the installed wheel, `ksef` with and without the `cli`
  extra, and no `tests/` in the sdist
* **docs:** the FA(3) schema README describes the real differences from the MF sources (line endings,
  the trailing whitespace in line 2258, and the **changed** `schemaLocation` in two files), and the
  integrity test pins that invariant instead of claiming the copies kept "original URLs"; the CLI
  documentation stops promising a `preflight` command (the function is not wired to any command),
  documents `cache.corrupt-<timestamp>.json` next to `config.corrupt-…`, marks exit code 7 as
  reserved, and uses the working global-option syntax (`ksef --json invoice list`); the
  datetime-parsing table is split by interpreter version (the basic `20250101T000000Z` format only
  parses from 3.11)
* **fa3:** a settlement invoice (`ROZ`/`KOR_ROZ`) is calculated like the official `FA_3_Przykład_14.xml`:
  `P_15` is the amount still to pay (`amount_due − charges + deductions`) and `P_13_x`/`P_14_x` are the
  line values scaled by `P_15 / order value` (the rounding remainder goes to the largest bucket, so
  `P_15 = ΣP_13_x + ΣP_14_x` holds to the cent). The SDK used to *require* pre-scaled lines and rejected
  the official shape
* **fa3:** the facet table carries the remaining schema constraints (`BDO`/`StopkaFaktury` `minLength=1`,
  `TNaturalny` `totalDigits=14`) and the engine now enforces `total_digits` at all (it was declared but
  never checked, so amount types with `totalDigits=18/22` accepted over-long numbers)
* **fa3:** `NoweSrodkiTransportu` without a row was XSD-invalid while `validate()` stayed silent; rows
  without the flag were dropped; `NewTransportMeans.kind` is validated (`land`/`water`/`air`, with working
  hours required for water/air) instead of silently falling back to the land branch
* **fa3:** `PaymentTerms.due_dates` is merged with `due_terms` instead of being ignored when `due_terms`
  is non-empty, and `paid_date` together with `partial_payments` is reported
* **cli:** profile names are validated (they become `sessions/<profile>/` path segments), `profile delete`
  removes stored tokens and checkpoints (with `--keep-credentials` to opt out), and `session export`
  refuses to overwrite a file without `--overwrite`
* **cli:** the cache lock is never taken over from a live owner (`os.kill(pid, 0)` on POSIX) — an aged
  `mtime` alone used to be enough to break mutual exclusion; `session import` accepts only known KSeF
  hosts unless `--allow-foreign-host` is given
* **utils:** `split_bytes` enforces the contractual limit of 50 package parts (KSeF rejects more with
  error 21161) and `VerificationLinkService` percent-encodes path segments, so a `/` in an identifier can
  no longer change the link structure (or the string signed for KOD II)
* **tools:** `sync_generated.py --check` no longer overwrites the tracked OpenAPI snapshot — the check
  used to create the very drift it reported
* **http:** a presigned URL (`skip_auth`) never follows a redirect, whatever `follow_redirects`
  says. The security validation covers only the initial address and no `Authorization` header is
  sent, so following a redirect performed a request to a server-chosen address (including the
  internal network) and returned its body as the result
* **cli:** the token metadata cache lock heals itself. A process killed mid-run left
  `cache.json.lock` behind and every later call failed after a 5 s wait until someone deleted the
  file by hand; a lock older than 30 s is now taken over (at most a few attempts, then the ordinary
  timeout applies), and lock/directory errors are reported as `CliError` instead of a raw `OSError`
* **cli:** the fallback token store lock (`tokens.json.lock`) heals the same way — a process killed
  mid-run used to block every token save and `auth logout` until the lock file was removed by hand
* **cli:** the checkpoint `base_url` guard honours `--base-url` and `KSEF_BASE_URL`. A session
  opened with an address override could not be sent or closed at all (the guard compared only with
  the profile), and the `send`/`close`/`status`/`import`/`batch upload`/`batch close` commands did
  not even offer `--base-url`
* **cli:** `auth logout` fails loudly when the fallback token store cannot be rewritten. The error
  used to be swallowed, so the command reported "Stored tokens removed." and `logged_out: true`
  while a valid refresh token stayed in `tokens.json`
* **packaging:** `requirements.txt` declares `typing-extensions` instead of leaving it to a
  transitive dependency. `documents/fa3` imports `Self` from `typing_extensions` on Python < 3.11
  (`from typing import Self` exists only from 3.11), and `requirements.txt` is a documented
  installation path — the dependency was declared in `pyproject.toml` only, so a bare
  `pip install -r requirements.txt` worked by accident (`anyio`/`cryptography` pull it in)
* **utils:** `fast_extract_ksef_metadata` reports order rows separately: invoice rows (`FaWiersz`)
  keep `total_netto`/`total_brutto`/`item_count`, while `ZamowienieWiersz` rows land in
  `order_netto`/`order_brutto`/`order_item_count` (gross = `P_11NettoZ + P_11VatZ`) and `StanPrzedZ`
  rows are skipped. Order/settlement documents used to be reported as empty (`total_netto=0.00`,
  `item_count=0`) with no signal — but the order value must not masquerade as the invoice amount
  (official `FA_3_Przykład_10.xml`: `WartoscZamowienia` 375150 vs `P_15` 20000)
* **services:** the CSR builder accepts the SDK model's own field names (`given_name`, `last_name`,
  `common_name`, …) next to the camelCase ones. A caller passing `given_name` — the exact field of
  `CertificateEnrollmentDataResponse` — silently got a CSR without `givenName` (2.5.4.42), which KSeF
  rejects with error 25003
* **cli:** the checkpoint `base_url` comparison ignores a default port (`https://host:443` ==
  `https://host`) and the error names the effective command address, not the profile
* **cli:** an imported session checkpoint can no longer decide where the profile's access token goes.
  `session import` compared only the profile *name*, so a crafted checkpoint file with a foreign
  `base_url` sent the KSeF token (and the invoice body) to that host on `session online send`,
  `close` and `status`. The base URL is now verified at import time and at every use site
* **cli:** a partial keyring write no longer leaves a mixed pair (new access token + stale refresh
  token) that looks complete and shadows the fallback store; a failed keyring delete now makes
  `auth logout` fail instead of claiming "Stored tokens removed."
* **cli:** the token metadata cache is written atomically and guarded by a cross-process lock —
  concurrent runs used to overwrite each other and lose profile metadata — and an invalid cache is
  quarantined with a warning, like `config.json` already was
* **utils:** `fast_extract_ksef_metadata` handles `P_11A` (gross, art. 106e ust. 7 and 8) instead of
  returning `total_netto=0.00`/`item_count=0` for such invoices, and skips rows marked `StanPrzed`,
  so a KOR/KOR_ROZ document is no longer counted twice (624000 → 312000 for `Fa_3_Przykład_18.xml`)
* **utils:** `unzip_bytes_safe`/`unzip_bytes`/`untar_gz_bytes*` default to the export package limit
  (10 000 invoices + `_metadata.json`), so the documented "use it for export packages" advice works
  without passing `max_files` by hand
* **utils:** the `COLLECTIVE_IDENTIFIER_EXCEPTION_CODES[71001]` description matches the contract
  ("invoice does not exist") instead of describing a different situation
* **fa3:** the advance payment feeds the rate summary for **every** invoice kind again. Restricting
  it to `ZAL` left `KOR_ZAL` with an empty `P_13_x`/`P_14_x` while `P_15` still contained the
  advance — a document without a tax base for that amount. The schema describes `P_15` as
  containing `P_15Z`, so `P_15 = ΣP_13_x + ΣP_14_x` must hold for all kinds
* **fa3:** `ZamowienieWiersz` has no discount field, so `P_9AZ` now carries the price **after** the
  discount: the schema's identity `P_8BZ × P_9AZ == P_11NettoZ` holds that way in every official
  sample that carries `P_9AZ` (`FA_3_Przykład_10.xml`–`_13.xml`). A 100 zł discount on
  20 × 1000 zł used to emit `P_9AZ=1000` with `P_11NettoZ=18000`
* **fa3:** `TaxCategory.from_vat_rate()` keeps the rate code — `0 WDT`/`0 EX` no longer collapse to
  `0 KR`, and `oo`/`np I`/`np II` are no longer declared as tax-exempt
* **fa3:** `FA3Line.to_dict()` writes `vat_code` first, so a JSON round-trip no longer turns `oo`,
  `np I` or `np II` into `zw`
* **fa3:** the draft no longer loses the exemption basis (`P_19A`) when a non-exempt line comes
  first: only `zw` lines are consulted, so `P_19N=1` can no longer contradict `P_13_7 > 0`
* **fa3:** `DaneKontaktowe` is limited to 3 per party (schema `maxOccurs="3"`) and the serializer no
  longer truncates the list silently; `Platnosc/ZaplataCzesciowa` is limited to 100
* **fa3:** `LineIdentifiers.unique_id` reaches `UU_ID` (it was ignored on invoice lines while every
  other field of that class worked)
* **fa3:** `InvoiceLine.period_from`/`period_to`/`additional_description` are reported instead of
  being dropped — the schema has `OkresFa`/`DodatkowyOpis` only at the `Fa` level
* **fa3:** `attachment_text()` and `attachment_table()` append blocks instead of replacing the whole
  attachment, so `attachment_text(...).attachment_table(...)` no longer loses the text
* **fa3:** the draft requires an address and no longer fabricates one (`AdresL1 = "brak"`) or invented
  buyer contacts (`brak@example.com`, `000000000`)
* **http:** a 3xx response is an error unless explicitly expected — `httpx` does not follow
  redirects, so the body was the intermediary's page or empty, and `upo download` wrote an empty
  file while reporting success
* **workflows:** the export package may contain 10 000 invoices **plus** `_metadata.json`; the
  contract excludes the metadata file from the package limits, so `max_files=10_000` rejected a
  legal maximum package
* **hwm:** a truncated metadata response resumes from the **last record's** `permanentStorageDate`
  when the API does not return `lastPermanentStorageDate` (the OpenAPI contract has no such field).
  Resuming from `permanentStorageHwmDate` (equal to `dateRange.to`) skipped every invoice between
  the last record and the watermark
* **csr:** the CSR carries `givenName` (2.5.4.42) and `surname` (2.5.4.4); the MF documentation
  requires the exact DN attributes returned by the enrolment endpoint
* **cli:** `auth refresh` no longer invents `method="token"` when the token cache has no method
  recorded — that made `auth revoke-self-token` revoke the company's KSeF token for a profile that
  authenticated with XAdES
* **security:** reject a KSeF public certificate whose validity bounds cannot be parsed and pick the
  newest one by real instant. On Python 3.10 every 7-digit API timestamp failed to parse, so
  `_is_current_certificate` accepted **expired** certificates and `max()` returned the first list
  element instead of the newest certificate
* **cli:** the CLI carried two private copies of that same certificate-validity bug
  (`cli/sdk/adapters.py`, `cli/auth/manager.py`), reachable from five call sites and covered by no
  offline test — both now use the shared tolerant parser and reject unparseable bounds
* **cli:** invoice sorting no longer degrades to lexical order on Python 3.10 (7-digit timestamps)
* **invoices:** date-range normalisation and the documented 100-day UTC guard no longer silently do
  nothing on Python 3.10
* **collective-identifiers:** accept the 7-digit timestamps KSeF itself returns (Python 3.10)
* **hwm:** `_permanent_storage_date_sort_key` compares real instants instead of the raw string, so the
  continuation point is the newest `permanentStorageDate`; a truncated package resumes from
  `LastPermanentStorageDate` (the MF-documented first case) instead of skipping to the server
  watermark and never fetching the invoices in between
* **fa3:** the facet engine applies the schema's `xsd:whiteSpace` mode per element — `collapse` for
  `xsd:token`/numeric/date types, `replace` for `xsd:normalizedString`, `preserve` for `xsd:string`
  (`TNrNIP`, `TNrRB`, `SWIFT`, `TNrKRS`, `TNrVatUE`, `TTekstowy`, `TNrREGON`). Stripping
  unconditionally let `<NIP> 1111111111</NIP>` (and `KodKraju=" PL "`) through the default
  `to_xml()` although the schema rejects them; measuring the raw value rejected schema-valid
  documents such as a padded `P_2`. The mode table is verified against the schema by a test
* **fa3:** the facet engine no longer rejects schema-valid documents — it resolves `xsd:token`
  whitespace, honours element-level inline date restrictions, treats `<X/>` as an empty value
  (previously `text is None` bypassed validation entirely), tolerates comments/processing
  instructions, and accepts an empty `NKom`/`SKom` (`TZnakowy2` has `minLength=0`)
* **fa3:** `NrKSeFFaZaliczkowej` shares the `TNumerKSeF` pattern with `NrKSeFFaKorygowanej` — a
  35-character garbage KSeF number used to pass `validate()` and the default `to_xml()`
* **fa3:** `KodKraju` is checked against the 254-value `TKodKraju` dictionary, so a typo like `XX`
  is reported instead of producing a document KSeF rejects
* **fa3:** `DataWytworzeniaFa` uses the element's own lower bound (`2025-09-01`), not the wider
  `TDataCzas` bound, and `PrefiksPodatnika` outside `Podmiot1` is no longer over-rejected
* **fa3:** emit the elements the schema makes mandatory and the SDK omitted — `BlokDanych/MetaDane`
  in attachments (every attachment was schema-invalid), `ZamowienieWiersz` in an order, and
  `AdresPrzewoznika` for a transport carrier
* **fa3:** restrict `IDWew` to `Podmiot3` (`TPodmiot2` does not allow it) and stop emitting
  `PrefiksPodatnika` in `PodmiotUpowazniony` and for an authorized party
* **fa3:** reject a Polish purchaser whose NIP is placed in `KodUE`/`NrVatUE` or `KodKraju`/`NrID`
  (GEN-20/P2-16 of the MF brochure) — the schema accepts it, but KSeF never makes the invoice
  available to that buyer
* **fa3:** require `Podmiot1/PrefiksPodatnika` to be exactly `PL` (the element is `fixed="PL"`), in
  both the business validation and the facet pass
* **fa3:** normalise `P_8B`, `P_12_XII`, `KursWaluty*`, `KursUmowny` and `Udzial` to the 6 decimals
  the schema allows (`TIlosci`/`TProcentowy`), and format `P_9A`/`P_9B`/`P_10` with up to 8
  decimals (`TKwotowy2`) instead of 2
* **fa3:** teach the draft/JSON layer the `oo`, `np I` and `np II` rate codes and route each of them
  to its own `P_13_x` bucket, instead of rejecting them or booking them as tax-exempt
* **fa3:** accept a zero rate spelled `0.0`/`0e0`/`0,0` as `0 KR` — a bare `0` in `P_12` is not a
  member of `TStawkaPodatku` and KSeF rejected the document
* **fa3:** round monetary fields half-up in the writer (the validator already did), so a settlement
  charge of `0.005` no longer prints as `0.00` while its sum prints as `0.01`
* **fa3:** reject XML 1.0 control characters and empty values for `minLength=1` fields instead of
  returning unparseable or schema-invalid XML
* **fa3:** reject a `gross_amount` override that disagrees with net + VAT (tolerance 1 grosz),
  in both the typed and the draft path — previously it emitted `P_15 != P_13 + P_14`, which KSeF
  rejects, with `validate()` reporting success
* **fa3:** enforce the schema number pattern (`totalDigits`, no leading zeros, no exponent) on
  amounts, quantities and percentages; `P_15="007.50"` or `"1E+3"` no longer passes validation
* **fa3:** validate attachment tables (column count/rows limits, `Kol/@Typ` dictionary, and a
  `column_types` list shorter than `headers`, which silently dropped columns)
* **fa3:** reject half-filled pairs instead of dropping them silently — `KursUmowny`/`WalutaUmowna`
  and the two parts of `Skonto`
* **fa3:** emit `DodatkowyOpis/NrWiersza`, so an additional description can be tied to a specific
  invoice line
* **fa3:** `xsd_audit` now resolves named complex types across all four schema files (402 paths
  instead of 298 — a quarter of the schema, including mandatory elements, was invisible) and derives
  coverage status from the tags the serializer actually emits instead of a prefix-matched map that
  made `UNSUPPORTED` unreachable
* **collective-identifiers:** validate context invoice limits, common seller, finite payment amounts,
  precise UTC ranges, and resumable CLI pagination
* **verification-link:** sign QR II certificate URLs with the raw path and KSeF-compliant RSA-PSS parameters
* **cli:** read the UPO reference from `upo.pages[].referenceNumber`, so `send batch --wait-upo`,
  `session batch close --wait-upo` and `upo wait --batch-auto` no longer fail on a real session status
* **utils:** make `b64decode` reject the base64url alphabet instead of silently discarding it, so
  `_decode_base64_or_url` actually falls back and verification links keep the whole invoice hash
* **packaging:** declare `typing_extensions` unconditionally and import `Self` from `typing` on
  Python 3.11+ — the earlier `python_version < '3.11'` marker left `import
  ksef_client.documents.fa3` failing on Python 3.13+ whenever no unrelated package provided it
* **fa3:** put each VAT rate into its own `P_13_x`/`P_14_x` bucket in the draft XML instead of
  declaring every rate as basic-rate sales, and emit `0 KR` for a 0% line
* **fa3:** keep the sign in `parse_vat_rate`, so a negative VAT rate is reported as an error
  instead of being silently flipped to a positive one
* **fa3:** derive VAT and gross from the effective net amount so `net_amount` overrides keep
  `P_13_x + P_14_x == P_15`; exempt draft lines now require an `exemption_basis` (P_19A)
  instead of emitting a contradictory `P_19N`
* **fa3:** treat `P_10` as a per-unit discount (the schema describes it next to `P_9A`/`P_9B`, and the
  official `FA_3_Przykład_4.xml` confirms `P_11 = P_8B × (P_9A − P_10)`), so a 100 zł discount on
  20 × 1000 zł yields 18 000 zł instead of 19 900 zł of net and 437 zł of extra VAT
* **fa3:** `TaxCategory.margin()` no longer emits `P_12="np I"` — a margin-procedure line carries no
  rate, no `P_9A` and no `P_11` (official `FA_3_Przykład_8.xml`/`_19.xml`)
* **fa3:** the advance payment feeds the rate summary only for an advance invoice (`ZAL`); a
  settlement (`ROZ`) had it counted twice
* **fa3:** require `Podmiot1K/Adres`, and refuse to guess the `P_13_x` proportion of a settlement
  invoice — the SDK now asks for rows that match the amount due instead of declaring the wrong tax
* **sessions:** request UPO downloads with `Accept: application/xml`, the only media type the contract
  declares
* **testdata:** the limit endpoints answer `200` with an empty body, so they now use the optional-model
  request helper instead of failing to deserialize
* **verification-link:** use the contracted KOD II segment spelling (`Nip`, `InternalId`, `NipVatUe`,
  `PeppolId`) and validate a string `issue_date`, which previously produced links the KSeF page
  rejects as malformed (`2026/02/01` even injected an extra path segment)
* **utils:** `MAX_BATCH_PART_SIZE_BYTES` is 100 MB decimally (`100_000_000`), the limit KSeF actually
  enforces per pre-encryption part; `build_zip` sanitises entry names like `build_tar_gz`, and both
  readers reject duplicate entry names instead of silently dropping content

## 0.21.0 (2026-10-27)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat(sdk): klient uwierzytelniony z auto-refresh i retry HTTP by @smekcio in https://github.com/smekcio/ksef-client-python/pull/101
* feat(errors): taksonomia błędów z kodami KSeF i to_dict by @smekcio in https://github.com/smekcio/ksef-client-python/pull/103
* feat(errors): taksonomia błędów dokumentów by @smekcio in https://github.com/smekcio/ksef-client-python/pull/104
* feat: niezawodna paginacja z kursorami i obowiązkowa brama TEST przed publikacją by @smekcio in https://github.com/smekcio/ksef-client-python/pull/105
* docs: pokaż w README paginację z kursorami i HWM by @smekcio in https://github.com/smekcio/ksef-client-python/pull/106
* feat: multi-year invoice searches and shared API rate budgets by @smekcio in https://github.com/smekcio/ksef-client-python/pull/108
* chore(packaging): enrich PyPI package metadata by @smekcio in https://github.com/smekcio/ksef-client-python/pull/111
* feat(sdk): fasada sync/async, wznawianie operacji i eksport strumieniowy by @smekcio in https://github.com/smekcio/ksef-client-python/pull/110


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.20.0...v0.21.0

## 0.20.0 (2026-10-21)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat(sdk): odczyt FA(3), profile, magazyn certyfikatów i paginacja metadanych by @smekcio in https://github.com/smekcio/ksef-client-python/pull/99


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.19.0...v0.20.0

## 0.19.0 (2026-10-15)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* fix: review findings across SDK, CLI, FA(3) and packaging + security hardening + KSeF API 2.9.0 by @smekcio in https://github.com/smekcio/ksef-client-python/pull/96
* fix(test): repair Python 3.10/3.11 matrix failure + run matrix on PRs by @smekcio in https://github.com/smekcio/ksef-client-python/pull/98


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.18.1...v0.19.0

## 0.18.1 (2026-09-29)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* fix: stabilize encrypted private key errors by @smekcio in https://github.com/smekcio/ksef-client-python/pull/92


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.18.0...v0.18.1

## 0.18.0 (2026-09-29)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat: align with KSeF API 2.8.1 by @smekcio in https://github.com/smekcio/ksef-client-python/pull/90


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.17.1...v0.18.0

## 0.17.1 (2026-08-30)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* fix: harden collective identifier workflows by @smekcio in https://github.com/smekcio/ksef-client-python/pull/85


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.17.0...v0.17.1

## 0.17.0 (2026-08-29)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat: add collective identifier helpers and CLI ksef iz by @smekcio in https://github.com/smekcio/ksef-client-python/pull/83


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.16.1...v0.17.0

## 0.16.1 (2026-08-12)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* refactor(xml): add streaming iterparse metadata extractor (ReDoS-free & Decimal precision) by @prefixus in https://github.com/smekcio/ksef-client-python/pull/80

## New Contributors
* @prefixus made their first contribution in https://github.com/smekcio/ksef-client-python/pull/80

**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.16.0...v0.16.1

## 0.16.0 (2026-07-27)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat: align with KSeF API 2.7.0 by @smekcio in https://github.com/smekcio/ksef-client-python/pull/77


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.15.0...v0.16.0

## 0.15.0 (2026-06-12)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat: align with KSeF API 2.6.1 by @smekcio in https://github.com/smekcio/ksef-client-python/pull/72


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.14.0...v0.15.0

## 0.14.0 (2026-05-20)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat: support KSeF API 2.6.0 by @smekcio in https://github.com/smekcio/ksef-client-python/pull/69


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.13.0...v0.14.0

## 0.13.0 (2026-05-17)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* feat: FA(3) z walidacją XSD by @smekcio in https://github.com/smekcio/ksef-client-python/pull/66


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.12.5...v0.13.0

## 0.12.5 (2026-05-11)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* Fix export HWM guard for non-PermanentStorage date ranges by @smekcio in https://github.com/smekcio/ksef-client-python/pull/64


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.12.4...v0.12.5

## 0.12.4 (2026-05-10)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* fix: handle empty invoice export packages by @smekcio in https://github.com/smekcio/ksef-client-python/pull/61


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.12.3...v0.12.4

## 0.12.3 (2026-05-07)

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### Changes
* docs: refresh KSeF 2.5 compatibility wording by @smekcio in https://github.com/smekcio/ksef-client-python/pull/58


**Full Changelog**: https://github.com/smekcio/ksef-client-python/compare/v0.12.2...v0.12.3

## [0.12.2](https://github.com/smekcio/ksef-client-python/compare/v0.12.1...v0.12.2) (2026-05-07)


### Bug Fixes

* **ci:** pin demo xades auth request schema to 2.0 ([39eb7fb](https://github.com/smekcio/ksef-client-python/commit/39eb7fbf60fd729c3c7c1f4d787108aaa2eb447c))

## [0.12.1](https://github.com/smekcio/ksef-client-python/compare/v0.12.0...v0.12.1) (2026-04-22)


### Features

* **cli:** add resumable session support ([a30d9ea](https://github.com/smekcio/ksef-client-python/commit/a30d9ea0b8d88bd8224207ad9a883c0da81c499e))


### Bug Fixes

* **cli:** harden resumable session recovery paths ([dd068c7](https://github.com/smekcio/ksef-client-python/commit/dd068c7d420550eb52cd22865b051067e2ad6409))


### Miscellaneous Chores

* release 0.12.1 ([1ef4fca](https://github.com/smekcio/ksef-client-python/commit/1ef4fca4f21b5e3521cce3f89874dae5f0ef5b85))

## [0.12.0](https://github.com/smekcio/ksef-client-python/compare/v0.11.0...v0.12.0) (2026-04-22)


### Features

* **cli:** add resumable online and batch sessions ([c4e10d4](https://github.com/smekcio/ksef-client-python/commit/c4e10d4a26be8c80cb1e2af65cc922b8899218cc))
* **cli:** add resumable online and batch sessions ([267e9e0](https://github.com/smekcio/ksef-client-python/commit/267e9e0b4b7e92c6cb8b096451620097435bacf2))


### Bug Fixes

* **ci:** avoid duplicate e2e runs on prs ([fc43ff6](https://github.com/smekcio/ksef-client-python/commit/fc43ff6183b8c3c91c814a26574e0d13935aa596))
* **ci:** harden flaky test e2e runs ([d997249](https://github.com/smekcio/ksef-client-python/commit/d997249f1b05a1f2b3cdf6d272070f57bad2d36c))
* **ci:** stabilize resumable session checks ([81059c6](https://github.com/smekcio/ksef-client-python/commit/81059c607fb2409259f7c87876447ed51c36730c))

## [0.11.0](https://github.com/smekcio/ksef-client-python/compare/v0.10.2...v0.11.0) (2026-04-20)


### Features

* **cli/export:** support incremental HWM options and enforce Asc sort ([5b71efb](https://github.com/smekcio/ksef-client-python/commit/5b71efbb87fdc903ff27edcc4fdfb54b59bfc98a))
* **cli/invoice-list:** stream multi-subject merge and expose metadata flags ([7787b41](https://github.com/smekcio/ksef-client-python/commit/7787b41ed6807d76bbe38c82f63746a54e453a0b))


### Bug Fixes

* **cli/auth:** make self token revoke deterministic and safe ([c02983f](https://github.com/smekcio/ksef-client-python/commit/c02983f0a2e4b7e634584cd44160a65f9073eec7))
* **cli/invoice-list:** enforce date-range and page-size constraints ([4392d69](https://github.com/smekcio/ksef-client-python/commit/4392d698df8a613f6b1f90aa4bef68f959a6e2ec))
* **cli/invoices:** validate page offset and harden HWM merge ([cddafbc](https://github.com/smekcio/ksef-client-python/commit/cddafbc87e1c9450b8b528ee94a66671bad9c65b))
* **cli:** remove export sort-order no-op and harden invoice list aggregation ([970c98d](https://github.com/smekcio/ksef-client-python/commit/970c98d1b4c7f1d849d86a6b45a9d292d92a2e7b))
* **cli:** remove export sort-order no-op and tighten invoice aggregation semantics ([901602d](https://github.com/smekcio/ksef-client-python/commit/901602d5fe89625d5ef2439521799d5d81c836d9))


### Documentation

* **cli:** align invoice/export docs with new behavior ([7ea8eaa](https://github.com/smekcio/ksef-client-python/commit/7ea8eaa627c91c5bbdfcc53b1a8e89b3696f5dd9))

## [0.10.2](https://github.com/smekcio/ksef-client-python/compare/v0.10.1...v0.10.2) (2026-04-20)


### Bug Fixes

* correct QR II verification-link signing ([103a0a4](https://github.com/smekcio/ksef-client-python/commit/103a0a415b0e6a70c26a759d88c5a8740105dd5f))
* **verification-link:** correct QR II signing and add e2e checks ([93887ae](https://github.com/smekcio/ksef-client-python/commit/93887aecc1d70b8ad86dbeace1662564d966c606))

## [0.10.1](https://github.com/smekcio/ksef-client-python/compare/v0.10.0...v0.10.1) (2026-04-19)


### Bug Fixes

* support encrypted private key passwords in verification link ([fafc0ec](https://github.com/smekcio/ksef-client-python/commit/fafc0ece6a2d333c570c252342dc8c39597db4d2))
* **verification-link:** support encrypted private key passwords ([e4c6989](https://github.com/smekcio/ksef-client-python/commit/e4c69899f9f688b23472e9f263cbe3142b63e776))


### Documentation

* **readme:** clarify typed-model rollout ([6eb1ffb](https://github.com/smekcio/ksef-client-python/commit/6eb1ffbe258931a3274cdb59d63b138cc306a3b4))
* **readme:** clarify typed-model rollout ([45a2e76](https://github.com/smekcio/ksef-client-python/commit/45a2e764c8c2ffc0b5658b837f03190d7b2156c2))

## [0.10.0](https://github.com/smekcio/ksef-client-python/compare/v0.9.0...v0.10.0) (2026-04-13)


### Features

* add KSeF 2.4 problem details and self-revoke support ([6fffbf8](https://github.com/smekcio/ksef-client-python/commit/6fffbf84244337bdcc963713e41f1c70bf7c8a68))
* **api:** handle KSeF 2.4 problem details and self-revoke ([701e91f](https://github.com/smekcio/ksef-client-python/commit/701e91f6088d866659ffac9ab1bc786c01f27133))


### Bug Fixes

* **cli:** enable problem-details by default ([cf76f28](https://github.com/smekcio/ksef-client-python/commit/cf76f28dd19a7bceaf81aa1b32391022aa4642ce))
* **cli:** recover self-revoke token reference ([a362399](https://github.com/smekcio/ksef-client-python/commit/a362399905b294fb8ed34c4b15d24bf27fad2869))


### Documentation

* describe KSeF 2.4 changes and typed model migration ([3a9dde4](https://github.com/smekcio/ksef-client-python/commit/3a9dde4ddaa422fe0270fefa781aad70acf83e3a))
* **tokens:** clarify self-revoke fallback ([2762c7a](https://github.com/smekcio/ksef-client-python/commit/2762c7a9f8ccfe87f4409255c4e5764611b0adae))
## [0.9.0](https://github.com/smekcio/ksef-client-python/compare/v0.8.0...v0.9.0) (2026-04-03)


### Features

* **api:** enforce typed payloads and strict OpenAPI validation ([7d2da52](https://github.com/smekcio/ksef-client-python/commit/7d2da5229251e5b1aee006955a6a28975ba7332a))
* **api:** move SDK to typed models and harden OpenAPI tooling ([4dbbb97](https://github.com/smekcio/ksef-client-python/commit/4dbbb97baddf0a7e2d45e9c2adde9cfa265fb8a9))
* **api:** move SDK to typed models and harden OpenAPI tooling ([eac4109](https://github.com/smekcio/ksef-client-python/commit/eac41098e7feaf0fd947e4fa8bfadcf3931ad949))


### Bug Fixes

* **api:** resolve typed payload regressions ([9233c97](https://github.com/smekcio/ksef-client-python/commit/9233c97f338b5f3cf7f0a7c9f0f17c58b3ce2907))
* **ci:** align lint and dependency submission checks ([9f8f263](https://github.com/smekcio/ksef-client-python/commit/9f8f2639a271f7cf7226605c7d067a041fb6047e))
* **cli:** bootstrap optional CLI dependencies ([93f04f4](https://github.com/smekcio/ksef-client-python/commit/93f04f472eac6b533f9866d30cac84fd7fa09821))
* **cli:** bootstrap optional CLI dependencies ([81dab12](https://github.com/smekcio/ksef-client-python/commit/81dab120f204f8f245467303dcbd3783b7df3fc1))
* **cli:** default invoice list to all subject types ([58d2878](https://github.com/smekcio/ksef-client-python/commit/58d287885611eaec6abba519fcccdc1dc5cf8cd0))
* default invoice list to all subject types ([52b93c0](https://github.com/smekcio/ksef-client-python/commit/52b93c006effc7f23f7bd8900de4b549f13428fa))
* **invoices:** avoid double serializing typed payloads ([144a924](https://github.com/smekcio/ksef-client-python/commit/144a9243b61aa4bd9368980425face8797820707))
* **lint:** avoid getattr false-positive in model test ([320d0bc](https://github.com/smekcio/ksef-client-python/commit/320d0bc94323efc97b8ede4a969efafe0cfb4aed))
* **models:** align typed exports, stubs, and HWM fallback ([6f1006b](https://github.com/smekcio/ksef-client-python/commit/6f1006b1d8595a3fd5fb8f855150a5b727fe0fd0))
* **models:** preserve typed response fields and test regressions ([8061c03](https://github.com/smekcio/ksef-client-python/commit/8061c03c59b107bc7fcdef081a4d2e91f82063a9))
* **models:** restore live API compatibility for e2e flows ([1fd9ac9](https://github.com/smekcio/ksef-client-python/commit/1fd9ac9561a955c9e779f47b57e052e8f8e8ae08))
* **test:** satisfy lint checks ([ea24b15](https://github.com/smekcio/ksef-client-python/commit/ea24b15893e1ec93e8ec217077223f1be130b1f6))
* **tests:** stabilize model smoke checks in ci ([5cae2d6](https://github.com/smekcio/ksef-client-python/commit/5cae2d659262515cf500b1b43f8f903595fa8240))

## [0.8.0](https://github.com/smekcio/ksef-client-python/compare/v0.7.1...v0.8.0) (2026-03-19)


### Features

* **api:** align SDK with KSeF API 2.3.0 ([32484e8](https://github.com/smekcio/ksef-client-python/commit/32484e8ff502cc0c6b33310c6b657d42a778d153))
* **api:** align SDK with KSeF API 2.3.0 ([a4561ab](https://github.com/smekcio/ksef-client-python/commit/a4561abb5f94c8c9c8b54de545d4fad0393c2a46))

## [0.7.1](https://github.com/smekcio/ksef-client-python/compare/v0.7.0...v0.7.1) (2026-03-11)


### Documentation

* align SDK docs and CLI tests with KSeF API 2.2.1 ([47e4bdd](https://github.com/smekcio/ksef-client-python/commit/47e4bdd94f015c093ce94bab81d510b890c46086))
* align SDK docs and CLI tests with KSeF API 2.2.1 ([04e9846](https://github.com/smekcio/ksef-client-python/commit/04e98468685e001b42841659895bf6a32e9636e4))
* trim redundant 2.2.1 notes ([f9554c9](https://github.com/smekcio/ksef-client-python/commit/f9554c979808a4de41218f6a48554aabcc08238e))

## [0.7.0](https://github.com/smekcio/ksef-client-python/compare/v0.6.0...v0.7.0) (2026-03-03)


### Features

* **api:** align sdk with KSeF API 2.2.0 ([5aa70ca](https://github.com/smekcio/ksef-client-python/commit/5aa70ca9a127fb88588d993979f972b0ed317dd4))
* **api:** align SDK with KSeF API 2.2.0 ([9583341](https://github.com/smekcio/ksef-client-python/commit/95833416ce778bd7488a249a66b289bd55134f38))

## [0.6.0](https://github.com/smekcio/ksef-client-python/compare/v0.5.0...v0.6.0) (2026-02-25)


### Features

* **cli:** add token-store policy visibility and plaintext warnings ([fc8e779](https://github.com/smekcio/ksef-client-python/commit/fc8e77951824e6290f50f3796241767f05d268df))
* **cli:** add token-store policy visibility and plaintext warnings ([3249bda](https://github.com/smekcio/ksef-client-python/commit/3249bda53efbda9052d117971ad7871efb251bbb))
* **cli:** harden auth secret input handling ([d7b7336](https://github.com/smekcio/ksef-client-python/commit/d7b733653d31c7b802feba894d7a9bbdb0913e32))
* **cli:** harden auth secret input handling ([99887c7](https://github.com/smekcio/ksef-client-python/commit/99887c78d2dca9537b19b3555ee33853b378b652))
* **cli:** implement DX-first KSeF CLI with docs and tests ([295fb6e](https://github.com/smekcio/ksef-client-python/commit/295fb6e47865878f03a2fa3b800112e8b1a57c1b))
* **cli:** KSeF CLI with docs and tests ([#15](https://github.com/smekcio/ksef-client-python/issues/15)) ([797adfd](https://github.com/smekcio/ksef-client-python/commit/797adfdafdf1bd9df5baf83d738a6f243cb2b4f3))
* **lighthouse:** add full latarnia SDK+CLI support with models, docs, and tests ([bec2ef4](https://github.com/smekcio/ksef-client-python/commit/bec2ef438263b4803783fa5dcbedc0a933645c4b))
* **lighthouse:** add public Latarnia API support in SDK and CLI ([897e15b](https://github.com/smekcio/ksef-client-python/commit/897e15b012497f152c3304edbe7c36196f14b67f))
* **security:** enforce export part hash verification ([966c895](https://github.com/smekcio/ksef-client-python/commit/966c89572c5353c9993495f82135937414e73d1e))
* **security:** enforce export part hash verification ([2744e21](https://github.com/smekcio/ksef-client-python/commit/2744e21859c1f1f9dd917e39441a54d8d05d54b0))
* **security:** validate presigned URLs for skip-auth transport ([81bc405](https://github.com/smekcio/ksef-client-python/commit/81bc405c7f7890bd036338a042198e5a9a367a43))
* **security:** validate presigned URLs for skip-auth transport ([5ec3626](https://github.com/smekcio/ksef-client-python/commit/5ec36265f2e15f7e9ee221bdbafd5ad4af1281cc))


### Bug Fixes

* **ci:** cover auth secret-source guard paths ([ba4400a](https://github.com/smekcio/ksef-client-python/commit/ba4400a38745abf1b6b812b0722acc4d46766aa4))
* **ci:** cover health token-store check normalization ([439d2ce](https://github.com/smekcio/ksef-client-python/commit/439d2ce430c6bb3994c3820ecbf45fc0ab815359))
* **ci:** restore 100% coverage and ignore lighthouse in main openapi check ([d72f2b3](https://github.com/smekcio/ksef-client-python/commit/d72f2b3657b10380d959dc13bcaaf9ce47659fe3))
* **ci:** satisfy lint and 100% coverage for presigned URL hardening ([15144c7](https://github.com/smekcio/ksef-client-python/commit/15144c7113aefddc5d82559a4daa432125bb02a2))
* **ci:** satisfy ruff checks for export hash workflow tests ([ce38add](https://github.com/smekcio/ksef-client-python/commit/ce38add5972e83e67392bf04874400cd53b33127))
* **ci:** stabilize CLI tests and restore 100% coverage ([e2ff607](https://github.com/smekcio/ksef-client-python/commit/e2ff6076ad63d56b51a24c75d6931ad15ccb32f2))
* **lighthouse:** allow no-profile CLI fallback and harden openapi parity path parsing ([bff593d](https://github.com/smekcio/ksef-client-python/commit/bff593d940c68d647c68b0808ba05335ac430a88))


### Documentation

* **readme:** refresh README copy and table of contents ([4743f5c](https://github.com/smekcio/ksef-client-python/commit/4743f5c0592803e7d0193696bf8059cf35305589))
* remove DX-first wording from documentation ([15140ab](https://github.com/smekcio/ksef-client-python/commit/15140ab91179e8c8a943a5982c9c2ec4baa30af7))

## [0.5.0](https://github.com/smekcio/ksef-client-python/compare/v0.4.0...v0.5.0) (2026-02-19)


### Features

* align python sdk with ksef docs 2.1.2 ([a87599a](https://github.com/smekcio/ksef-client-python/commit/a87599a2ec2c725e8fcea2eb4df5f2c5c763d337))
* align python sdk with ksef docs 2.1.2 ([843c8a5](https://github.com/smekcio/ksef-client-python/commit/843c8a50ea52f1b7ca40cc98eeb0c116cd9ec131))

## [0.4.0](https://github.com/smekcio/ksef-client-python/compare/v0.3.1...v0.4.0) (2026-02-14)


### Features

* align SDK with KSeF API v2.1.1 ([0355fe4](https://github.com/smekcio/ksef-client-python/commit/0355fe44d2d6ac0aa0bb4146f9b67331c62b6b92))
* align SDK with KSeF API v2.1.1 ([0355fe4](https://github.com/smekcio/ksef-client-python/commit/0355fe44d2d6ac0aa0bb4146f9b67331c62b6b92))
* align SDK with KSeF API v2.1.1 ([01fd0ae](https://github.com/smekcio/ksef-client-python/commit/01fd0aeda7287dca945ca481b004cdbb09089806))
* **ci:** add end-to-end KSeF workflows for TEST and DEMO (token + XAdES) ([d420d58](https://github.com/smekcio/ksef-client-python/commit/d420d5814a749e464ebcea108857aee138fff3fb))
* **ci:** add end-to-end KSeF workflows for TEST and DEMO (token + XAdES) ([d420d58](https://github.com/smekcio/ksef-client-python/commit/d420d5814a749e464ebcea108857aee138fff3fb))


### Bug Fixes

* **ci:** Allow manual PyPI publish from main branch without tag verif… ([4d74384](https://github.com/smekcio/ksef-client-python/commit/4d7438467aa5124842be69eda694eb76b0329826))
* **ci:** Allow manual PyPI publish from main branch without tag verification ([2f179c5](https://github.com/smekcio/ksef-client-python/commit/2f179c53c372a1747415cc5707df70497cdab902))
* **ci:** dodać E2E KSeF i poprawić release-please ([c0df915](https://github.com/smekcio/ksef-client-python/commit/c0df915f8d7db808367ef5c31ba2a13ec70be772))
* **ci:** use PAT secret for release-please action ([8891024](https://github.com/smekcio/ksef-client-python/commit/8891024cb84d59bdf170a44fe6b1f649cf9b5e48))


### Documentation

* **readme:** add GitHub Actions badges for E2E test jobs ([e04a6bb](https://github.com/smekcio/ksef-client-python/commit/e04a6bb277b0d685d675f86445d1b743c7d452d9))
* **readme:** split Python E2E badge links by job ([91ffef2](https://github.com/smekcio/ksef-client-python/commit/91ffef258879df1734384e1102ed3beea4396701))
* **readme:** use single Python E2E workflow badge ([accbbec](https://github.com/smekcio/ksef-client-python/commit/accbbec87e923ce291988d54c4288ce9b92dddb3))

## [0.3.1](https://github.com/smekcio/ksef-client-python/compare/v0.3.0...v0.3.1) (2026-01-18)


### Bug Fixes

* **ci:** Trigger PyPI publish on release published event ([9d0223d](https://github.com/smekcio/ksef-client-python/commit/9d0223da78bbb6a2678d12d7762ccf0e3dfded76))
* **ci:** Trigger PyPI publish on release published event ([1c843a1](https://github.com/smekcio/ksef-client-python/commit/1c843a14fc8356b25a2e62c53786759797537e1c))

## [0.3.0](https://github.com/smekcio/ksef-client-python/compare/v0.2.0...v0.3.0) (2026-01-18)


### Features

* **ci:** Enhance coverage check with Deprecation and Status Code validation ([119982e](https://github.com/smekcio/ksef-client-python/commit/119982eb6a3dcfa363fc7cbe27f8b7e0a4d6414b))
* Implement comprehensive API compliance verification in CI ([5978bc2](https://github.com/smekcio/ksef-client-python/commit/5978bc28cb5aa772581783cbf7d1543cfb3faca8))
* Implement comprehensive API compliance verification in CI ([316a890](https://github.com/smekcio/ksef-client-python/commit/316a8908d7608b924969a5013909e1f51b500535))


### Bug Fixes

* **ci:** Resolve Ruff linting issues in generated files and tools ([1cf8748](https://github.com/smekcio/ksef-client-python/commit/1cf8748e57bfaf204e72c71f318c95bdad4cdaa8))
* Restore AsyncSecurityClient class definition missing after refactor ([e1ef032](https://github.com/smekcio/ksef-client-python/commit/e1ef032bf489c64d9da5977d0bb39f9db9826c95))
* **tools:** Auto-fix import sorting in check_coverage.py to satisfy Ruff ([7450b01](https://github.com/smekcio/ksef-client-python/commit/7450b0188e6b054c01ac7e5fdc54402e74fc127a))
* Update openapi_models.py to match latest generator changes (Ruff noqa placement) ([07fd209](https://github.com/smekcio/ksef-client-python/commit/07fd209f1cefc890d937613f92803a337636a4aa))


### Documentation

* **readme:** make documentation links clickable ([6aca86a](https://github.com/smekcio/ksef-client-python/commit/6aca86a3e0b36547015240d56f29dc363c893f3c))
* **readme:** rewrite README (docs links, quick start, snippets) ([2beacf7](https://github.com/smekcio/ksef-client-python/commit/2beacf7c5261b6776e80b0df86b395e3a89dd2b9))
* **readme:** rewrite README (docs links, quick start, snippets) ([d41d32d](https://github.com/smekcio/ksef-client-python/commit/d41d32d7f02011a23d6311cb57ee10d67cea4839))
