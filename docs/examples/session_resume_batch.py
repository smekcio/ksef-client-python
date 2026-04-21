from __future__ import annotations

import os
from pathlib import Path

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client import models as m
from ksef_client.services import AuthCoordinator, BatchSessionState, BatchSessionWorkflow


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
    zip_path = Path(_env("KSEF_BATCH_ZIP_PATH"))
    state_path = Path(os.getenv("KSEF_BATCH_STATE_PATH", "batch-session-state.json"))

    zip_bytes = zip_path.read_bytes()

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

        workflow = BatchSessionWorkflow(client.sessions, client.http_client)
        session = workflow.open_session(
            form_code=m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA"),
            zip_bytes=zip_bytes,
            public_certificate=symmetric_cert_pem,
            access_token=access_token,
        )
        state_path.write_text(session.get_state().to_json(), encoding="ascii")

    resumed_state = BatchSessionState.from_json(state_path.read_text(encoding="ascii"))

    with KsefClient(KsefClientOptions(base_url=base_url), access_token=access_token) as client:
        resumed = BatchSessionWorkflow(client.sessions, client.http_client).resume_session(
            resumed_state,
            zip_bytes=zip_bytes,
        )
        resumed.upload_parts(parallelism=4)
        resumed.close()

    print(f"Saved state to: {state_path}")
    print(f"Session reference: {resumed_state.reference_number}")


if __name__ == "__main__":
    main()
