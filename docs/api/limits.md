# Limity (`client.limits`)

## `get_context_limits(access_token)`

Endpoint: `GET /limits/context`

Zwraca limity zależne od kontekstu (sesje oraz `collectiveIdentifier.maxInvoices`).

## `get_subject_limits(access_token)`

Endpoint: `GET /limits/subject`

Zwraca limity zależne od podmiotu (np. certyfikaty).



Od API 2.10.0 `get_context_limits()` zwraca również `tokens.max_tokens`,
czyli limit tokenów rev2 w bieżącym kontekście. Pole `tokens` może być
`None`, np. na środowisku działającym na API 2.9.0.
