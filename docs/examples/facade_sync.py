"""Explicitly invoked TEST examples. Sends invoices/permissions only for the chosen action."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ksef_client import Ksef, KsefClientOptions, KsefEnvironment, OperationState, TokenCredentials
from ksef_client import models as m


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
    args = parser.parse_args()
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
                client.resume_operation(
                    OperationState.from_dict(json.loads(args.resume_state.read_text()))
                )
                if args.resume_state
                else client.exports.start(filters)
            )
            if args.save_state:
                # The example application owns persistence; SDK never writes keys automatically.
                with args.save_state.open("x", encoding="utf-8") as output:
                    os.chmod(args.save_state, 0o600)
                    output.write(operation.resume_state().to_json())
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
