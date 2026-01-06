# Przykłady (Python)

Katalog zawiera minimalne skrypty uruchomieniowe prezentujące podstawowe scenariusze:
- autoryzacja tokenem KSeF (uzyskanie `accessToken` i `refreshToken`),
- autoryzacja podpisem XAdES (certyfikat + klucz prywatny albo kontener PKCS#12),
- wyszukiwanie metadanych faktur,
- wysyłka faktury w sesji online (XML FA(3) z pliku).

Polecenia w tym dokumencie zakładają uruchomienie z katalogu `ksef-client-python`.

## Wymagania

- Python `>= 3.10`
- Zainstalowana biblioteka lokalnie: `pip install -e .`
- Dostęp do środowiska KSeF oraz dane uwierzytelniające

## Zmienne środowiskowe

Podstawowe:

- `KSEF_CONTEXT_TYPE` – typ identyfikatora kontekstu, np. `nip`
- `KSEF_CONTEXT_VALUE` – wartość identyfikatora kontekstu, np. NIP
- `KSEF_BASE_URL` – URL środowiska (opcjonalnie; domyślnie DEMO)

Autoryzacja tokenem:

- `KSEF_TOKEN` – token KSeF (systemowy)

## Skrypty

### `auth_xades_cert_key.py`

Uzyskuje tokeny (`accessToken`, `refreshToken`) w oparciu o podpis XAdES.

Wymagania dodatkowe:

```bash
pip install -e .[xml]
```

Dodatkowe zmienne:

- `KSEF_XADES_PKCS12` – ścieżka do kontenera PKCS#12 (`.pfx` / `.p12`) zawierającego certyfikat i klucz prywatny
- `KSEF_XADES_PKCS12_PASSWORD` – hasło do kontenera PKCS#12 (opcjonalnie; zależnie od pliku)
- `KSEF_XADES_CERT_PEM` – ścieżka do certyfikatu (PEM albo DER `.crt`) – używane, gdy nie ustawiono `KSEF_XADES_PKCS12`
- `KSEF_XADES_KEY_PEM` – ścieżka do klucza prywatnego (PEM/DER; dopuszczalny klucz zaszyfrowany hasłem) – używane, gdy nie ustawiono `KSEF_XADES_PKCS12`
- `KSEF_XADES_KEY_PASSWORD` – hasło do klucza prywatnego (opcjonalnie)
- `KSEF_SUBJECT_IDENTIFIER_TYPE` – np. `certificateSubject` albo `certificateFingerprint` (domyślnie `certificateSubject`)

Uruchomienie:

```bash
python docs/examples/auth_xades_cert_key.py
```

### `auth_ksef_token.py`

Uzyskuje tokeny (`accessToken`, `refreshToken`) na podstawie tokena KSeF.

Uruchomienie:

```bash
python docs/examples/auth_ksef_token.py
```

### `invoice_list.py`

Zwraca metadane ostatnich faktur z zakresu dat (domyślnie 30 dni wstecz).

Dodatkowe zmienne:

- `KSEF_SUBJECT_TYPE` – np. `Subject1` (domyślnie `Subject1`)
- `KSEF_DATE_RANGE_DAYS` – liczba dni wstecz (domyślnie `30`)
- `KSEF_PAGE_SIZE` – rozmiar strony (domyślnie `10`)

Uruchomienie:

```bash
python docs/examples/invoice_list.py
```

### `invoice_send.py`

Wysyła fakturę w sesji online. Skrypt zakłada dostępność poprawnego pliku XML faktury w wersji FA(3).

Dodatkowe zmienne:

- `KSEF_INVOICE_XML_PATH` – ścieżka do pliku XML (FA(3))

Uruchomienie:

```bash
python docs/examples/invoice_send.py
```
