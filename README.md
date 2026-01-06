# KSeF Client Python

`ksef-client-python` jest biblioteką (SDK) dla **KSeF API 2.0 (v2)**. Zakres obejmuje:

- klientów API (`KsefClient`, `AsyncKsefClient`) mapujących wywołania na endpointy,
- warstwę workflow (`ksef_client.services.workflows`) porządkującą typowe scenariusze integracyjne (uwierzytelnianie, sesje, eksport),
- kryptografię i narzędzia pomocnicze (AES/ZIP/Base64Url, linki weryfikacyjne, QR),
- uwierzytelnianie tokenem KSeF oraz podpisem XAdES (w tym `XadesKeyPair` dla PKCS#12 / PEM+hasło).

Zachowania protokołu (np. pre-signed URL bez nagłówka `Authorization`, `Retry-After` dla `429`) są opisane w dokumentacji i odwzorowane w modelach wyjątków.

## Instalacja (lokalnie)

```bash
pip install -e .
```

## Opcjonalne dodatki (extras)

```bash
pip install -e .[xml,qr]
```

- `xml` – podpis XAdES (`lxml`, `xmlsec`)
- `qr` – generowanie PNG z kodami QR (`qrcode`, `pillow`)

## Dokumentacja

Dokumentacja pakietu znajduje się w katalogu `docs/`:

- Indeks: `docs/README.md`
- Start: `docs/getting-started.md`
- Konfiguracja: `docs/configuration.md`
- Błędy i retry: `docs/errors.md`
- API (endpointy): `docs/api/README.md`
- Workflows: `docs/workflows/README.md`
- Usługi: `docs/services/README.md`
- Utils: `docs/utils/README.md`
- Przykłady (skrypty): `docs/examples/README.md`

## Narzędzia developerskie

- `tools/generate_openapi_models.py` – generacja `src/ksef_client/openapi_models.py` na podstawie `ksef-docs/open-api.json`.
- `tools/lint.py` – lokalny runner jakości (m.in. `compileall`, `pip check`, opcjonalnie `ruff` i `mypy`).

## Testy

```bash
pytest
```

