from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client import models as m
from ksef_client.services import AuthCoordinator


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise SystemExit(f"Set {name} env var.")
    return value


def main() -> None:
    base_url = _env("KSEF_BASE_URL", KsefEnvironment.DEMO.value)
    token = _env("KSEF_TOKEN")
    context_type = _env("KSEF_CONTEXT_TYPE")
    context_value = _env("KSEF_CONTEXT_VALUE")

    subject_type = os.getenv("KSEF_SUBJECT_TYPE", "Subject1")
    page_size = int(os.getenv("KSEF_PAGE_SIZE", "10"))
    date_range_days = int(os.getenv("KSEF_DATE_RANGE_DAYS", "30"))

    date_to = datetime.now(timezone.utc)
    date_from = date_to - timedelta(days=date_range_days)

    with KsefClient(KsefClientOptions(base_url=base_url)) as client:
        token_cert_pem = client.security.get_public_key_certificate_pem(
            m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
        )
        access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
            token=token,
            public_certificate=token_cert_pem,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            max_attempts=90,
            poll_interval_seconds=2.0,
        ).access_token

        metadata = client.invoices.query_invoice_metadata_by_date_range(
            subject_type=m.InvoiceQuerySubjectType(subject_type),
            date_type=m.InvoiceQueryDateType.ISSUE,
            date_from=date_from.isoformat(),
            date_to=date_to.isoformat(),
            access_token=access_token,
            page_size=page_size,
        )

    invoices = metadata.invoices
    print(f"Invoices returned: {len(invoices)}")
    for invoice in invoices:
        print(invoice.to_dict())


if __name__ == "__main__":
    main()
