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

### `query_authorizations_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/authorizations/grants`

### `query_entities_roles(..., access_token)`
Endpoint: `GET /permissions/query/entities/roles`

### `query_eu_entities_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/eu-entities/grants`

### `query_personal_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/personal/grants`

### `query_persons_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/persons/grants`

### `query_subordinate_entities_roles(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/subordinate-entities/roles`

### `query_subunits_grants(request_payload, ..., access_token)`
Endpoint: `POST /permissions/query/subunits/grants`
