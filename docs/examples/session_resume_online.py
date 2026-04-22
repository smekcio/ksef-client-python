from __future__ import annotations

import os
import time
from pathlib import Path

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client import models as m
from ksef_client.services import AuthCoordinator, OnlineSessionState, OnlineSessionWorkflow


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
    state_path = Path(os.getenv("KSEF_SESSION_STATE_PATH", "online-session-state.json"))

    invoice_xml = Path(invoice_xml_path).read_bytes()

    with KsefClient(KsefClientOptions(base_url=base_url)) as client:
        token_cert_pem = client.security.get_public_key_certificate_pem(
            m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
        )
        symmetric_cert_pem = client.security.get_public_key_certificate_pem(
            m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION,
        )
        access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
            token=token,
            public_certificate=token_cert_pem,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            max_attempts=90,
            poll_interval_seconds=2.0,
        ).access_token

        workflow = OnlineSessionWorkflow(client.sessions)
        session = workflow.open_session(
            form_code=m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA"),
            public_certificate=symmetric_cert_pem,
            access_token=access_token,
        )
        state_path.write_text(session.get_state().to_json(), encoding="ascii")

    resumed_state = OnlineSessionState.from_json(state_path.read_text(encoding="ascii"))

    with KsefClient(KsefClientOptions(base_url=base_url), access_token=access_token) as client:
        resumed = OnlineSessionWorkflow(client.sessions).resume_session(resumed_state)
        send_result = resumed.send_invoice(invoice_xml)
        invoice_reference = send_result.reference_number

        status = None
        for _ in range(60):
            status = resumed.get_invoice_status(invoice_reference)
            code = int(status.status.code)
            if code == 200:
                break
            if code not in {100, 150}:
                raise RuntimeError(status.to_dict())
            time.sleep(2)

        resumed.close()

    print(f"Saved state to: {state_path}")
    print(f"Invoice reference: {invoice_reference}")
    print(f"KSeF number: {None if status is None else status.ksef_number}")


if __name__ == "__main__":
    main()
