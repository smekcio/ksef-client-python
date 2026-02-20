# Plan Rozwoju SDK pod Adopcje i DX (`ksef-client-python`)

## Podsumowanie
Ten dokument jest celowo przebudowany pod cele uzgodnione wczesniej: najpierw Quick Wins zwiekszajace adopcje i DX, a potem inicjatywy 2-3 kwartaly budujace przewage produktu. Priorytet: skracanie czasu startu integracji, mniejsza liczba bledow produkcyjnych i lepsza operacyjnosc.

## Cele glowne (zgodne z ustaleniami)

### Quick Wins (1-2 miesiace)
1. Oficjalne CLI dla obu SDK.
2. Tryb dry-run/diagnostic.
3. Standaryzowany mechanizm retry + circuit breaker.
4. Silniejsza walidacja wejscia.
5. Gotowe copy-paste starters.

### Inicjatywy 2-3 kwartaly
1. Pluginy/framework adapters.
2. Observability SDK (OpenTelemetry + metrics).
3. Background jobs orchestration kit.
4. Offline/test kit i mock server.
5. Generator SDK artifacts z OpenAPI.

## Plan wdrozenia (Python)

## Faza A (marzec-kwiecien 2026): Quick Wins

### A1. Oficjalne CLI (`ksef-cli`)
Zakres:
- Dodanie entrypoint `ksef-cli` w `pyproject.toml`.
- Komendy: `auth token`, `auth xades`, `invoice list`, `session online-send`, `session batch-send`, `export run`, `health check`.
- Reuzycie `KsefClient`, `AuthCoordinator`, `OnlineSessionWorkflow`, `BatchSessionWorkflow`, `ExportWorkflow`.

Zmiany publicznego API/interfejsu:
- Nowy interfejs CLI jako stabilny surface dla developerow.
- Brak zmian breaking w API Pythona.

Definition of Done:
- CLI dziala dla DEMO/TEST.
- Komendy maja `--help`, poprawne kody wyjscia i czytelne bledy.
- Dokumentacja CLI dodana do `docs/`.

### A2. Tryb dry-run/diagnostic
Zakres:
- Walidacja configu, certyfikatow, env vars, endpointu, tokenow, payloadu bez wysylki biznesowej.
- Komenda `ksef-cli health check --dry-run`.
- Raport z jasnymi remediacjami.

Zmiany publicznego API/interfejsu:
- `DiagnosticsService` z metodami typu `run_preflight(...)`.
- Opcjonalny `dry_run=True` dla wybranych workflowow.

Definition of Done:
- Raport diagnozy pokrywa auth token + XAdES + podstawowy invoice flow.
- Testy jednostkowe i integracyjne dla najczestszych bledow.

### A3. Retry + circuit breaker
Zakres:
- Jeden model policy dla retry transportowego i ochrony przed lawina bledow.
- Backoff + jitter + honorowanie `Retry-After`.
- Circuit breaker na poziomie klienta HTTP.

Zmiany publicznego API/interfejsu:
- `RetryPolicy` i `CircuitBreakerPolicy` w opcjach klienta.
- Czytelne wyjatki: `RetryExhaustedError`, `CircuitOpenError`.

Definition of Done:
- Udokumentowane defaulty i override.
- Testy dla 429/5xx/timeouts + przejscia CLOSED->OPEN->HALF_OPEN.

### A4. Silniejsza walidacja wejscia
Zakres:
- Pre-validacja request payloadow przed HTTP.
- Kontekstowe komunikaty bledow (ktore pole, jaki format, jak naprawic).

Zmiany publicznego API/interfejsu:
- `ValidationErrorDetails` w bledach domenowych.
- Walidacja na granicy klienta i workflowow.

Definition of Done:
- Brak wysylki HTTP dla oczywiscie blednych danych.
- Testy walidacji dla auth/sessions/export.

### A5. Gotowe starters
Zakres:
- Minimalne sample: FastAPI + worker (Celery/RQ) + przykładowy pipeline auth->send->upo.
- Szybka instrukcja uruchomienia lokalnego.

Zmiany publicznego API/interfejsu:
- Brak breaking changes; nowe repo-sample i docs.

Definition of Done:
- Co najmniej 2 uruchamialne startery.
- Przechodza smoke testy lokalne.

## Faza B (Q3 2026): Skalowanie adopcji

### B1. Pluginy/framework adapters
- Adaptery do FastAPI i Django (middleware, lifecycle tokenow, domyslne policy retry).
- API: `install_ksef_fastapi(...)`, `install_ksef_django(...)`.

### B2. Observability SDK
- Hooki i instrumentacja OpenTelemetry.
- Metryki: latency, retry count, error rate, poll duration.
- Redaction danych wrazliwych.

### B3. Background jobs orchestration kit
- Trwale joby dla UPO polling i eksportu.
- Resume po restarcie, idempotency key, deduplikacja.

## Faza C (Q4 2026): Niezawodnosc i utrzymanie

### C1. Offline/test kit i mock server
- Lokalny mock KSeF z gotowymi scenariuszami success/failure/throttle.
- Deterministyczne fixture do CI.

### C2. Generator artifacts z OpenAPI
- Polautomatyczna synchronizacja modeli/typow na bazie `ksef-docs/open-api.json`.
- Kontrola driftu kontraktu przed release.

## Zmiany publicznego API (target)
- `KsefClientOptions.retry_policy: RetryPolicy | None`
- `KsefClientOptions.circuit_breaker: CircuitBreakerPolicy | None`
- `DiagnosticsService.run_preflight(...) -> DiagnosticReport`
- `HealthCheckService.check_connectivity(...) -> HealthReport`
- `JobCoordinator` dla dlugich workflowow (polling/export)
- Hooki: `on_request`, `on_retry`, `on_error`, `on_workflow_event`

## Plan testow

### Unit
- Retry policy, circuit breaker, walidatory wejscia, parser raportu diagnostycznego.

### Integration
- Testy HTTP z symulacja 429/5xx/timeouts.
- Testy adapterow FastAPI/Django.

### E2E
- Istniejace flow token/XAdES + scenariusze CLI.
- Smoke dla starterow.

### Contract
- Utrzymanie parity endpointow i modeli z OpenAPI.
- Gate release: parity + tests + docs.

## KPI
1. Time-to-first-success < 30 min.
2. Spadek issue integracyjnych (auth/config/payload) min. 50%.
3. Co najmniej 2 stabilne startery i 1 oficjalne CLI.
4. 100% endpoint parity utrzymane.
5. Wzrost adopcji workflowow wysokiego poziomu vs low-level API.

## Ryzyka i mitigacje
- Ryzyko: API drift KSeF.
  Mitigacja: automatyczny diff OpenAPI + release gate.
- Ryzyko: rosnaca zlozonosc retry.
  Mitigacja: jeden centralny model policy i telemetry.
- Ryzyko: flaky E2E.
  Mitigacja: mock server + podzial smoke/full.

## Zaleznosci
- Stabilny dostep do srodowisk TEST/DEMO.
- Sekrety CI dla flow token/XAdES.
- Aktualny `ksef-docs/open-api.json`.

## Harmonogram kwartalny
- Q2 2026: CLI, dry-run, retry+circuit breaker, walidacja, starters.
- Q3 2026: framework adapters, observability, orchestration kit.
- Q4 2026: mock server/test kit, generator artifacts, hardening release.

## Zalozenia domyslne
- Wszystkie zmiany additive-first, bez breaking changes dla istniejacego API.
- Security by default: redaction danych wrazliwych.
- Dokumentacja i DX sa traktowane jako czesc produktu, nie dodatek.

## Checklista Sprint 1
- [ ] RFC dla `ksef-cli` i zestawu komend.
- [ ] Projekt `DiagnosticsService` + format `DiagnosticReport`.
- [ ] Implementacja `RetryPolicy` i `CircuitBreakerPolicy`.
- [ ] Minimalna walidacja wejscia dla auth/sessions/export.
- [ ] Pierwszy starter FastAPI + worker.
- [ ] Testy unit/integration i aktualizacja docs.
