# Workflow: uwierzytelnianie (XAdES / token KSeF)

W procesie uwierzytelniania uzyskiwany jest `accessToken` (JWT), wykorzystywany w większości endpointów chronionych.

Dostępne są dwa podejścia:
- użycie workflow `AuthCoordinator`,
- użycie metod `client.auth.*` (pełna kontrola nad wywołaniami).

## Wariant A: token KSeF

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.services import AuthCoordinator

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    certs = client.security.get_public_key_certificates()
    token_cert_pem = next(
        c["certificate"]
        for c in certs
        if "KsefTokenEncryption" in (c.get("usage") or [])
    )

    result = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token=KSEF_TOKEN,
        public_certificate=token_cert_pem,
        context_identifier_type=CONTEXT_TYPE,
        context_identifier_value=CONTEXT_VALUE,
        method="rsa",  # albo "ec"
        ec_output_format="java",
        max_attempts=90,
        poll_interval_seconds=2.0,
    )

    access_token = result.tokens.access_token.token
    refresh_token = result.tokens.refresh_token.token
```

`method="ec"` ma uzasadnienie m.in. w następujących przypadkach:
- porównywanie wyników z SDK Java/.NET (podejście zgodne z tymi implementacjami),
- środowiska oparte o klucze EC.

## Wariant B: XAdES (certyfikat + klucz prywatny)

Wymaga:

```bash
pip install -e .[xml]
```

```python
from ksef_client.services import AuthCoordinator, XadesKeyPair

key_pair = XadesKeyPair.from_pkcs12_file(
    pkcs12_path="cert.pfx",
    pkcs12_password="haslo",
)

result = AuthCoordinator(client.auth).authenticate_with_xades_key_pair(
    key_pair=key_pair,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
    subject_identifier_type="certificateSubject",
    verify_certificate_chain=None,
    max_attempts=90,
    poll_interval_seconds=2.0,
)
access_token = result.tokens.access_token.token
```

W przypadku posiadania certyfikatu i klucza jako osobnych plików dostępne jest również wczytanie przez `XadesKeyPair.from_pem_files(...)`.

Challenge jest ważny ok. 10 minut. W przypadku dłuższego procesu podpisu (np. HSM/podpis kwalifikowany) wymagane jest pobranie nowego wyzwania.

## Odświeżanie `accessToken` (refresh)

Refresh token jest wysyłany jako `Authorization: Bearer <refreshToken>`. W bibliotece:

```python
new_tokens = client.auth.refresh_access_token(refresh_token)
access_token = new_tokens["accessToken"]["token"]
```

## Najczęstsze problemy

- `401` po statusie auth: w `get_auth_status()` idzie **authentication token**, nie `accessToken`.
- `400` na `redeem`: ponowne wywołanie dla tego samego `authenticationToken`.
- `403` po świeżym nadaniu uprawnień: operacja uprawnień jeszcze się nie zakończyła (polling po statusie).
