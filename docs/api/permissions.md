# Uprawnienia (`client.permissions`)

Większość operacji w tym obszarze jest asynchroniczna (202) i wymaga sprawdzania statusu po numerze referencyjnym.

## Załączniki

### `check_attachment_permission_status(access_token)`

Endpoint: `GET /permissions/attachments/status`

Sprawdza, czy w danym kontekście/podmiocie dostępna jest obsługa załączników.

## Nadawanie / cofanie

Każda z tych metod zwykle zwraca `referenceNumber` operacji (202). Status operacji jest dostępny przez `get_operation_status(...)`.

### `grant_authorization(request_payload, access_token)`
Endpoint: `POST /permissions/authorizations/grants`

### `revoke_authorization(permission_id, access_token)`
Endpoint: `DELETE /permissions/authorizations/grants/{permissionId}`

### `revoke_common_permission(permission_id, access_token)`
Endpoint: `DELETE /permissions/common/grants/{permissionId}`

### `grant_entity(request_payload, access_token)`
Endpoint: `POST /permissions/entities/grants`

### `grant_eu_entity(request_payload, access_token)`
Endpoint: `POST /permissions/eu-entities/grants`

### `grant_eu_entity_admin(request_payload, access_token)`
Endpoint: `POST /permissions/eu-entities/administration/grants`

### `grant_indirect(request_payload, access_token)`
Endpoint: `POST /permissions/indirect/grants`

### `grant_person(request_payload, access_token)`
Endpoint: `POST /permissions/persons/grants`

### `grant_subunit(request_payload, access_token)`
Endpoint: `POST /permissions/subunits/grants`

## Status operacji

### `get_operation_status(reference_number, access_token)`

Endpoint: `GET /permissions/operations/{referenceNumber}`

Częsty scenariusz: `403` po nadaniu uprawnienia wynika z tego, że operacja nie zakończyła się jeszcze statusem „Succeeded”.

## Zapytania (query)

Wszystkie query wspierają `page_offset` i `page_size` (stronicowanie offsetowe).
`page_offset` to **numer strony** (0 = pierwsza), a `page_size` — liczba wyników na stronie.

### `query_authorizations_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/authorizations/grants`

### `query_entities_roles(..., access_token)`
Endpoint: `GET /permissions/query/entities/roles`

### `query_entities_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/entities/grants`

### `query_eu_entities_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/eu-entities/grants`

### `query_personal_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/personal/grants`

Odpowiedź zawiera `has_more`, `permissions` oraz — od KSeF API 2.9.0 — `owner_permissions`
(lista `OwnerPermissionScope`: `CredentialsManage`, `CredentialsRead`, `InvoiceWrite`,
`InvoiceRead`, `Introspection`, `SubunitManage`, `EnforcementOperations`,
`CollectiveIdentifierManage`), czyli uprawnienia właścicielskie kontekstu.

### `list_personal_grants`

Fasady `Ksef` i `AsyncKsef` pobierają wszystkie strony z
`POST /permissions/query/personal/grants` w bieżącym kontekście uwierzytelnienia.
Puste kryteria zapytania obejmują również nadania nieaktywne.

```python
# client jest zalogowaną instancją Ksef
report = client.permissions.list_personal_grants()
for grant in report.permissions:
    print(grant.permission_scope.value, grant.permission_state.value, grant.target_identifier)

if report.owner_permissions is not None:
    print("Uprawnienia właścicielskie", [scope.value for scope in report.owner_permissions])

# Dla zalogowanej instancji AsyncKsef
# report = await client.permissions.list_personal_grants()
```

Metoda zwraca `QueryPersonalPermissionsResponse` z `has_more=False`. Osobne nadania
tego samego uprawnienia zachowują własne identyfikatory, stan i zakres. Kody
właścicielskie zachowują kolejność pierwszej zgłoszonej listy. Jeśli dwie strony
podają różne zbiory kodów właścicielskich, metoda zgłasza `KsefPaginationError`
i można ponowić cały odczyt. `owner_permissions=None`
oznacza brak informacji na wszystkich stronach, a `[]` oznacza zgłoszoną pustą listę.

Parametr `max_pages` domyślnie wynosi 100 przy rozmiarze strony 100 nadań.
Klient ogranicza odpowiedź do 4 MiB na stronę i sprawdza liczbę zwróconych nadań.
Dla selektywnego uprawnienia wymagany jest identyfikator podmiotu docelowego.
Typ `AllPartners` oznacza wszystkich partnerów i ma pustą wartość.
Przekroczenie limitu, powtórzenie identyfikatora nadania lub pusta strona zapowiadająca
kolejne wyniki zgłasza `KsefPaginationError`. Błędy HTTP przechodzą do wywołującego.
KSeF zwraca strony kolejno, więc nadanie lub cofnięcie uprawnienia w trakcie odczytu
może wpłynąć na wynik. [Opis endpointu w dokumentacji MF](https://github.com/CIRFMF/ksef-api/blob/main/uprawnienia.md#pobranie-listy-w%C5%82asnych-uprawnie%C5%84)

### `query_persons_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/persons/grants`

### `query_subordinate_entities_roles(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/subordinate-entities/roles`

### `query_subunits_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/subunits/grants`
