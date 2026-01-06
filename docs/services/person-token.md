# Person token (`ksef_client.services.person_token`)

`PersonTokenService` to lekki parser claimów JWT dla person tokenów KSeF.

## Ważne ograniczenie (bezpieczeństwo)

Parser **nie weryfikuje podpisu JWT** i nie powinien być wykorzystywany do decyzji bezpieczeństwa (authz/authn). Narzędzie służy do inspekcji tokenów uznanych za zaufane (diagnostyka, logowanie, prezentacja danych).

## `PersonTokenService.parse(jwt_token) -> PersonToken`

Zwraca strukturę `PersonToken` z ujednoliconymi polami:

- `issuer`, `audiences`
- `issued_at`, `expires_at`
- role i uprawnienia: `roles`, `permissions`, `permissions_excluded`, `permissions_effective`
- kontekst: `context_id_type`, `context_id_value`
- szczegóły podmiotu (`subject_details`) i polityka IP (`ip_policy`) jeśli były obecne

Przykład:

```python
from ksef_client.services import PersonTokenService

token = PersonTokenService().parse(jwt_token)
print(token.context_id_type, token.context_id_value)
print(token.roles)
```
