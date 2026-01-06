# KSeF Client Python

`ksef-client-python` jest repozytorium biblioteki (SDK) publikowanej na PyPI jako: **`ksef-client`**.

Dokumentacja SDK (kanonicznie w repozytorium): `https://github.com/smekcio/ksef-client-python/blob/main/docs/README.md`

## Zakres

- Klienci API (`KsefClient`, `AsyncKsefClient`) mapujący wywołania na endpointy KSeF.
- Warstwa workflow (`ksef_client.services.workflows`) porządkująca scenariusze (uwierzytelnianie, sesje online/batch, eksport).
- Narzędzia kryptograficzne i pomocnicze (AES/ZIP/Base64Url, linki weryfikacyjne, QR).
- Uwierzytelnianie tokenem KSeF oraz podpisem XAdES (w tym `XadesKeyPair` dla PKCS#12 lub zestawu PEM+hasło).

Zachowania protokołu (m.in. pre-signed URL bez nagłówka `Authorization`, obsługa `Retry-After` dla `429`) są opisane w dokumentacji i odwzorowane w modelach wyjątków.

## Wymagania

- Python `>= 3.10`

## Instalacja (PyPI)

```bash
pip install ksef-client
```

Opcjonalne dodatki (extras):

```bash
pip install "ksef-client[xml,qr]"
```

- `xml` – podpis XAdES (`lxml`, `xmlsec`)
- `qr` – generowanie PNG z kodami QR (`qrcode`, `pillow`)

## Instalacja (developerska, lokalnie)

```bash
pip install -e .
```

## Dokumentacja

Dokumentacja pakietu znajduje się w katalogu `docs/`:

- Indeks: `https://github.com/smekcio/ksef-client-python/blob/main/docs/README.md`
- Start: `https://github.com/smekcio/ksef-client-python/blob/main/docs/getting-started.md`
- Konfiguracja: `https://github.com/smekcio/ksef-client-python/blob/main/docs/configuration.md`
- Błędy i retry: `https://github.com/smekcio/ksef-client-python/blob/main/docs/errors.md`
- API (endpointy): `https://github.com/smekcio/ksef-client-python/blob/main/docs/api/README.md`
- Workflows: `https://github.com/smekcio/ksef-client-python/blob/main/docs/workflows/README.md`
- Usługi: `https://github.com/smekcio/ksef-client-python/blob/main/docs/services/README.md`
- Utils: `https://github.com/smekcio/ksef-client-python/blob/main/docs/utils/README.md`
- Przykłady (skrypty): `https://github.com/smekcio/ksef-client-python/blob/main/docs/examples/README.md`

## Narzędzia developerskie

- `tools/generate_openapi_models.py` – generacja `src/ksef_client/openapi_models.py` na podstawie `ksef-docs/open-api.json`.
- `tools/lint.py` – lokalny runner jakości (m.in. `compileall`, `pip check`, opcjonalnie `ruff` i `mypy`).

## Testy

```bash
pytest
```
