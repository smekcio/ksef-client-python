# Migracja do typed model API

Ta nota dotyczy przejścia ze starszego stylu integracji, w ktorym requesty i odpowiedzi byly
traktowane glownie jako `dict`, do aktualnego kontraktu SDK opartego o `ksef_client.models`.

## Co sie zmienilo

- publiczne payloady requestow do klientow SDK sa `typed-only`
- wiele metod klientow zwraca modele odpowiedzi zamiast surowych `dict`
- starsze przyklady oparte o `{"field": ...}` oraz `response["field"]` nie sa juz docelowym stylem uzycia

W praktyce oznacza to, ze przy wywolaniach API trzeba konstruowac modele z `ksef_client.models`, a po stronie
odczytu korzystac z atrybutow obiektow i tylko na granicach integracji serializowac je przez `.to_dict()`.

## Kogo to dotyczy

Ta migracja dotyczy kodu, ktory:

- przekazuje do metod klientow surowe `dict` jako body JSON
- czyta odpowiedzi przez indeksowanie typu `response["field"]`
- zapisuje lub przekazuje dalej payloady bezposrednio w formie slownikow

Jesli korzystasz glownie z CLI `ksef`, zmiana zwykle Cie nie dotyczy bezposrednio.

## Najczestsze migracje

### 1. Auth token: certyfikat i access token

Przed:

```python
certs = client.security.get_public_key_certificates()
token_cert_pem = next(
    c["certificate"]
    for c in certs
    if "KsefTokenEncryption" in (c.get("usage") or [])
)

result = AuthCoordinator(client.auth).authenticate_with_ksef_token(
    token=KSEF_TOKEN,
    public_certificate=token_cert_pem,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
)
access_token = result.tokens.access_token.token
```

Po:

```python
from ksef_client import models as m
from ksef_client.services import AuthCoordinator

token_cert_pem = client.security.get_public_key_certificate_pem(
    m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
)

access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
    token=KSEF_TOKEN,
    public_certificate=token_cert_pem,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
).access_token
```

### 2. Query invoices: request z modelami zamiast `dict`

Przed:

```python
metadata = client.invoices.query_invoice_metadata(
    {
        "subjectType": "Subject1",
        "dateRange": {
            "dateType": "Issue",
            "from": "2026-01-01T00:00:00Z",
            "to": "2026-01-31T23:59:59Z",
        },
    },
    access_token=access_token,
    page_size=10,
)

for invoice in metadata["invoices"]:
    print(invoice["ksefNumber"])
```

Po:

```python
from ksef_client import models as m

metadata = client.invoices.query_invoice_metadata_by_date_range(
    subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
    date_type=m.InvoiceQueryDateType.ISSUE,
    date_from="2026-01-01T00:00:00Z",
    date_to="2026-01-31T23:59:59Z",
    access_token=access_token,
    page_size=10,
)

for invoice in metadata.invoices:
    print(invoice.ksef_number)
```

Jesli potrzebujesz jawnie zbudowac body requestu, utworz model z `models` i przekaz go do klienta:

```python
filters = m.InvoiceQueryFilters(
    subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
    date_range=m.InvoiceQueryDateRange(
        date_type=m.InvoiceQueryDateType.ISSUE,
        from_="2026-01-01T00:00:00Z",
        to="2026-01-31T23:59:59Z",
    ),
)

metadata = client.invoices.query_invoice_metadata(
    filters,
    access_token=access_token,
    page_size=10,
)
```

### 3. `form_code`: model zamiast slownika

Przed:

```python
session_reference_number = BatchSessionWorkflow(client.sessions, client.http_client).open_upload_and_close(
    form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
    zip_bytes=zip_bytes,
    public_certificate=symmetric_cert_pem,
    access_token=access_token,
)
```

Po:

```python
from ksef_client import models as m
from ksef_client.services.workflows import BatchSessionWorkflow

session_reference_number = BatchSessionWorkflow(client.sessions, client.http_client).open_upload_and_close(
    form_code=m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA"),
    zip_bytes=zip_bytes,
    public_certificate=symmetric_cert_pem,
    access_token=access_token,
)
```

## Jak budowac requesty z `models as m`

Zalecany wzorzec:

```python
from ksef_client import models as m

request_model = m.InvoiceQueryFilters(
    subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
    date_range=m.InvoiceQueryDateRange(
        date_type=m.InvoiceQueryDateType.ISSUE,
        from_="2026-01-01T00:00:00Z",
        to="2026-01-31T23:59:59Z",
    ),
)
response_model = client.invoices.query_invoice_metadata(
    request_model,
    access_token=access_token,
)
```

Preferuj:

- import `from ksef_client import models as m`
- jawne konstruktory modeli i enumow
- helpery wysokiego poziomu, jesli upraszczaja budowe payloadu, np. `query_invoice_metadata_by_date_range(...)`

Nie zakladaj kompatybilnosci wstecznej dla przekazywania surowych `dict` do publicznych metod klientow.

## Jak czytac odpowiedzi

Preferuj atrybuty modeli zamiast indeksowania:

```python
status = client.auth.get_auth_status(reference_number, authentication_token)

print(status.status.code)
print(status.authentication_method)
```

Zamiast:

```python
print(status["status"]["code"])
print(status["authenticationMethod"])
```

## Kiedy uzywac `.from_dict()` i `.to_dict()`

Te metody sa przydatne na granicach integracji:

- `.from_dict()` gdy masz payload spoza SDK i chcesz zamienic go na model
- `.to_dict()` gdy musisz zapisac model do JSON, zwrocic go z wlasnej warstwy API albo przekazac do obcego kodu

Przyklad:

```python
from ksef_client import models as m

filters = m.InvoiceQueryFilters.from_dict(external_payload)
result = client.invoices.query_invoice_metadata(filters, access_token=access_token)
payload_for_logging = result.to_dict()
```

Wewnatrz kodu aplikacyjnego preferuj prace na modelach tak dlugo, jak to mozliwe.
