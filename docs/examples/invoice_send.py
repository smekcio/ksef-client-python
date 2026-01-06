from __future__ import annotations

import os
import time
from pathlib import Path

from ksef_client.client import KsefClient
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.services.workflows import AuthCoordinator, OnlineSessionWorkflow


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
    invoice_xml_path = _env("KSEF_INVOICE_XML_PATH")

    invoice_xml = Path(invoice_xml_path).read_bytes()

    with KsefClient(KsefClientOptions(base_url=base_url)) as client:
        certs = client.security.get_public_key_certificates()
        token_cert_pem = next(
            c["certificate"]
            for c in certs
            if "KsefTokenEncryption" in (c.get("usage") or [])
        )
        symmetric_cert_pem = next(
            c["certificate"]
            for c in certs
            if "SymmetricKeyEncryption" in (c.get("usage") or [])
        )
        access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
            token=token,
            public_certificate=token_cert_pem,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            max_attempts=90,
            poll_interval_seconds=2.0,
        ).tokens.access_token.token

        workflow = OnlineSessionWorkflow(client.sessions)
        session = workflow.open_session(
            form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
            public_certificate=symmetric_cert_pem,
            access_token=access_token,
        )
        send_result = workflow.send_invoice(
            session_reference_number=session.session_reference_number,
            invoice_xml=invoice_xml,
            encryption_data=session.encryption_data,
            access_token=access_token,
        )
        invoice_reference = send_result["referenceNumber"]

        status = None
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

        workflow.close_session(session.session_reference_number, access_token)

    print(f"Invoice reference: {invoice_reference}")
    print(f"KSeF number: {None if status is None else status.get('ksefNumber')}")


if __name__ == "__main__":
    main()

