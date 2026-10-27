"""Explicitly invoked TEST examples. Sends invoices/permissions only for the chosen action."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from ksef_client import Ksef, KsefClientOptions, KsefEnvironment, OperationState, TokenCredentials
from ksef_client import models as m
from ksef_client.operations import STATE_MAX_BYTES


def _load_export_state(path: Path, key: bytes) -> OperationState:
    # Read at most the payload budget plus a bounded envelope, even for a bad file.
    with path.open("rb") as source:
        encrypted = source.read(STATE_MAX_BYTES + 128)
    return OperationState.from_encrypted_bytes(encrypted, key)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["online", "batch", "export", "permission", "certificate"]
    )
    parser.add_argument("--input", type=Path, help="XML, archive, or typed request JSON")
    parser.add_argument("--from", dest="start", default="2026-01-01")
    parser.add_argument("--to", dest="end", default="2026-01-02")
    parser.add_argument("--destination", default="export-result")
    parser.add_argument("--work-dir", default="export-work")
    parser.add_argument(
        "--resume-state", type=Path, help="Application-managed private operation state"
    )
    parser.add_argument(
        "--save-state", type=Path, help="Explicitly persist private state for this example"
    )
    parser.add_argument(
        "--state-key-env",
        default="KSEF_STATE_KEY",
        help="Environment variable containing a separately stored Base64 32-byte state key",
    )
    args = parser.parse_args()
    state_key = b""
    if args.save_state or args.resume_state:
        if args.action != "export":
            parser.error("State persistence is supported for the export action")
        state_key = base64.b64decode(os.environ[args.state_key_env], validate=True)
        if len(state_key) != 32:
            parser.error("The state key must contain exactly 32 bytes")
    with Ksef.connect(
        options=KsefClientOptions(base_url=KsefEnvironment.TEST.value),
        context_type="nip",
        context_value=os.environ["KSEF_NIP"],
        credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
    ) as client:
        if args.action == "export":
            filters = m.InvoiceQueryFilters(
                subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
                date_range=m.InvoiceQueryDateRange(
                    date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                    from_=args.start,
                    to=args.end,
                    restrict_to_permanent_storage_hwm_date=True,
                ),
            )
            operation = (
                client.resume_operation(_load_export_state(args.resume_state, state_key))
                if args.resume_state
                else client.exports.start(filters)
            )
            if args.save_state:
                # The example application owns persistence; SDK never writes keys automatically.
                encrypted = operation.resume_state().to_encrypted_bytes(state_key)
                fd = os.open(args.save_state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(encrypted)
            result = operation.download_to(args.destination, work_dir=args.work_dir, timeout=600)
            print(len(result.files))
        elif args.action in {"online", "batch"}:
            if args.input is None:
                parser.error("--input is required")
            if args.action == "online":
                with client.online_session() as session:
                    print(session.send_invoice(args.input.read_bytes()).wait().ksef_number)
            else:
                with client.batch_session(args.input.read_bytes()) as session:
                    session.upload_parts()
            session.wait()
            print(len(session.upo().wait().pages))
        else:
            if args.input is None:
                parser.error("--input is required")
            raw = json.loads(args.input.read_text(encoding="utf-8"))
            if args.action == "permission":
                operation = client.permissions.grant_person(
                    m.PersonPermissionsGrantRequest.from_dict(raw)
                )
            else:
                operation = client.certificates.send_enrollment(
                    m.EnrollCertificateRequest.from_dict(raw)
                )
            print(operation.wait().status.code)


if __name__ == "__main__":
    main()
