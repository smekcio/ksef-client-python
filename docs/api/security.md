# Security (`client.security`)

Te endpointy nie wymagają `accessToken` i są wykorzystywane m.in. do:
- szyfrowania tokena KSeF (cert o usage `KsefTokenEncryption`)
- szyfrowania klucza symetrycznego (cert o usage `SymmetricKeyEncryption`)

## `get_public_key_certificates()`

Endpoint: `GET /security/public-key-certificates`

Zwraca listę certyfikatów i ich `usage`. Typowy sposób użycia to wybór certyfikatów po `usage`:

```python
certs = client.security.get_public_key_certificates()
token_cert = next(c["certificate"] for c in certs if "KsefTokenEncryption" in (c.get("usage") or []))
sym_cert = next(c["certificate"] for c in certs if "SymmetricKeyEncryption" in (c.get("usage") or []))
```

## `get_public_key_pem()`

Endpoint: `GET /public-keys/publicKey.pem`

Zwraca PEM jako `str`.
