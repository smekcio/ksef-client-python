# `ksef` CLI - plan implementacyjny (stan aktualny)

## Status ogolny

CLI jest funkcjonalnie domkniete dla glownego flow DX:

1. `init` i profile,
2. `auth` (token + XAdES),
3. `invoice list/download`,
4. `send online/batch/status`,
5. `upo get/wait`,
6. `export run/status`.

## Jakosc

- testy CLI: `202 passed`
- coverage `ksef_client.cli`: `100%`

Uruchamianie:

```bash
pytest tests/cli -q
pytest tests/cli --cov=ksef_client.cli --cov-report=term-missing
```

## Etapy wdrozenia

## Etap 0 - scaffolding

Status: `completed`

## Etap 1 - auth i konfiguracja

Status: `completed`

Zakres zrealizowany:
- `auth login-token/status/refresh/logout`
- `auth login-xades`
- keyring + fallback plikowy token store

## Etap 2 - invoice i UPO

Status: `completed`

## Etap 3 - wysylka online i batch

Status: `completed`

## Etap 4 - export i health

Status: `completed`

## Etap 5 - hardening DX

Status: `completed`

Zakres domkniety:
- stabilny JSON contract (`meta.duration_ms`)
- czytelny output human (`invoice.list` jako tabela)
- dopracowane mapowanie bledow i hinty
- poprawiona logika `health check`
- fallback `base_url/context` z aktywnego profilu
- bezpieczniejsza polityka storage tokenow (brak plaintext fallback domyslnie)
- komplet testow fail-path + success-path

## Architektura CLI (utrzymana)

```text
src/ksef_client/cli/
  app.py
  context.py
  commands/
  auth/
  config/
  output/
  policies/
  sdk/
  diagnostics/

tests/cli/
  unit/
  integration/
  smoke/
```

## Dalszy backlog (opcjonalny)

1. Rozszerzenie diagnostyki (`diagnostics.checks`) o realne checki preflight i endpointy.
2. Snapshot tests dla `--help` i outputu human dla stabilizacji UX.
3. Dodatkowe E2E smoke z realnym KSeF w osobnym pipeline (sekrety + izolacja).
