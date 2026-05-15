# FA(3) SDK Only

Dokument opisuje programistyczny workflow FA(3) w warstwie SDK (`ksef_client.documents.fa3`).
Zakres obejmuje budowanie faktur, walidację biznesową, serializację XML oraz walidację XSD.

## Zakres SDK

Dostępne elementy publicznego API:
- modele i buildery: `FA3InvoiceBuilder`, `FA3Draft`, `FA3BatchDraft`,
- walidacja biznesowa: `build()` oraz `draft.validate()`,
- serializacja XML FA(3): `draft.to_xml(...)`,
- walidacja XSD: `draft.to_xml(xsd_validate=True)` oraz `validate_fa3_xml_xsd(...)`,
- eksport wsadowy: `to_xml_files(...)` i `to_xml_zip(...)`,
- JSON draft dla integracji: `to_dict/from_dict`, `to_json/from_json`.

## Instalacja

Do walidacji XSD wymagany jest extra `fa3`:

```bash
pip install -e .[fa3]
```

## Typowy przepływ

1. Zbuduj draft faktury przez `FA3InvoiceBuilder`.
2. Wywołaj `build()` (walidacja biznesowa).
3. Wygeneruj XML przez `to_xml(xsd_validate=True)`.
4. Dla wielu faktur użyj `FA3BatchDraft(...).to_xml_zip(...)` albo `to_xml_files(...)`.

## Przykłady

- `docs/examples/fa3_single_invoice_sdk.py`
- `docs/examples/fa3_batch_zip_sdk.py`
- `docs/examples/fa3_correction_settlement_sdk.py`
- `docs/examples/fa3_json_roundtrip_sdk.py`
