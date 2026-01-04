from __future__ import annotations

import json
import os
import time
from pathlib import Path

from ksef_client.client import KsefClient
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.services.workflows import AuthCoordinator, OnlineSessionWorkflow


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if not value:
        raise SystemExit(f"Set {name} env var.")
    return value


def main() -> None:
    token = _env("KSEF_TOKEN")
    context_type = _env("KSEF_CONTEXT_TYPE")
    context_value = _env("KSEF_CONTEXT_VALUE")
    base_url = _env("KSEF_BASE_URL", KsefEnvironment.DEMO.value)
    invoice_json_path = Path(
        _env("KSEF_INVOICE_JSON", "ksef-client-python/examples/data/invoice.json")
    )
    template_path = Path(
        _env(
            "KSEF_INVOICE_TEMPLATE",
            "ksef-client-python/examples/data/invoice-template-fa-3.xml",
        )
    )

    data = json.loads(invoice_json_path.read_text(encoding="utf-8"))
    template = template_path.read_text(encoding="utf-8")
    for key in [
        "sellerNip",
        "invoiceNumber",
        "issueDate",
        "issueDateTime",
        "periodFrom",
        "periodTo",
        "paymentDue",
    ]:
        if not data.get(key):
            raise SystemExit(f"Missing {key} in invoice JSON.")
    replacements = {
        "{{SELLER_NIP}}": data["sellerNip"],
        "{{INVOICE_NUMBER}}": data["invoiceNumber"],
        "{{ISSUE_DATE}}": data["issueDate"],
        "{{ISSUE_DATETIME}}": data["issueDateTime"],
        "{{PERIOD_FROM}}": data["periodFrom"],
        "{{PERIOD_TO}}": data["periodTo"],
        "{{PAYMENT_DUE}}": data["paymentDue"],
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)
    invoice_xml = template.encode("utf-8")

    with KsefClient(KsefClientOptions(base_url=base_url)) as client:
        certs = client.security.get_public_key_certificates()
        token_cert = next(c for c in certs if "KsefTokenEncryption" in (c.get("usage") or []))[
            "certificate"
        ]
        symmetric_cert = next(
            c for c in certs if "SymmetricKeyEncryption" in (c.get("usage") or [])
        )["certificate"]
        access_token = (
            AuthCoordinator(client.auth)
            .authenticate_with_ksef_token(
                token=token,
                public_certificate=token_cert,
                context_identifier_type=context_type,
                context_identifier_value=context_value,
                max_attempts=90,
                poll_interval_seconds=2.0,
            )
            .tokens.access_token.token
        )
        session = OnlineSessionWorkflow(client.sessions).open_session(
            form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
            public_certificate=symmetric_cert,
            access_token=access_token,
        )
        send_result = OnlineSessionWorkflow(client.sessions).send_invoice(
            session_reference_number=session.session_reference_number,
            invoice_xml=invoice_xml,
            encryption_data=session.encryption_data,
            access_token=access_token,
        )
        invoice_reference = send_result["referenceNumber"]
        for _ in range(60):
            status = client.sessions.get_session_invoice_status(
                session.session_reference_number,
                invoice_reference,
                access_token=access_token,
            )
            code = int(status.get("status", {}).get("code", 0))
            if code == 200:
                break
            if code not in {100, 150}:
                raise RuntimeError(status)
            time.sleep(2)
        OnlineSessionWorkflow(client.sessions).close_session(
            session.session_reference_number,
            access_token,
        )

    print(f"Invoice reference: {invoice_reference}")
    print(f"KSeF number: {status.get('ksefNumber')}")


if __name__ == "__main__":
    main()
