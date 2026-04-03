# Security (`client.security`)

Te endpointy nie wymagają `accessToken` i są wykorzystywane m.in. do:
- szyfrowania tokena KSeF (cert o usage `KsefTokenEncryption`)
- szyfrowania klucza symetrycznego (cert o usage `SymmetricKeyEncryption`)

## `get_public_key_certificates()`

Endpoint: `GET /security/public-key-certificates`

Zwraca listę certyfikatów i ich `usage`. Typowy sposób użycia to wybór certyfikatów po `usage`:

```python
from ksef_client import models as m

token_cert = client.security.get_public_key_certificate(
    m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
).certificate
sym_cert = client.security.get_public_key_certificate(
    m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION,
).certificate
```

Jeśli potrzebujesz pełnej listy, nadal możesz użyć `get_public_key_certificates()`. W typowych scenariuszach
czytelniejsze jest jednak `get_public_key_certificate(...)`.

## `get_public_key_pem()`

Endpoint: `GET /public-keys/publicKey.pem`

Zwraca PEM jako `str`.
