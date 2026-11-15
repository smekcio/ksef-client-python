"""Activate a versioned XAdES key and run a bounded offline invoice cycle."""

from __future__ import annotations

import argparse
import base64
import json
import os
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

from ksef_client import Ksef
from ksef_client.certificate_rotation import ProfileCertificates
from ksef_client.certificates import FileCertificateStore
from ksef_client.offline_invoices import OfflineInvoiceQueue, SQLiteOfflineInvoiceStore
from ksef_client.profiles import ProfileStore


def read_password(name: str) -> str:
    passwords = json.loads(os.environ["KSEF_XADES_KEY_PASSWORDS"])
    return passwords[name]


def open_queue(path: Path) -> SQLiteOfflineInvoiceStore:
    if not path.is_file():
        raise ValueError("--queue must refer to an existing staged offline queue")
    key = base64.b64decode(os.environ["KSEF_OFFLINE_STATE_KEY"], validate=True)
    return SQLiteOfflineInvoiceStore.open(path, key=key)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--selector", type=Path, required=True)
    parser.add_argument("--certificates", type=Path, required=True)
    parser.add_argument("--verify-chain", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--enforce-compliance", action="store_true")
    actions = parser.add_subparsers(dest="action", required=True)
    status = actions.add_parser("status")
    status.add_argument("--warn-days", type=int, default=30)
    activate = actions.add_parser("activate")
    activate.add_argument("name")
    activate.add_argument("--expected-generation", type=int, required=True)
    activate.add_argument("--fingerprint", action="store_true")
    activate.add_argument("--queue", type=Path, help="Verify access to existing invoice sessions.")
    run = actions.add_parser("run")
    run.add_argument("--queue", type=Path, required=True)
    run.add_argument("--limit", type=int, default=20, choices=range(1, 101))
    run.add_argument("--after-due-at")
    run.add_argument("--after-hash")

    args = parser.parse_args()

    profile = ProfileStore.default().get(args.profile)
    store = FileCertificateStore(args.certificates, require_password=True)
    selector = ProfileCertificates(
        args.selector,
        profile,
        store=store,
        verify_certificate_chain=args.verify_chain,
        enforce_xades_compliance=args.enforce_compliance,
    )
    if args.action == "status":
        health = selector.status(warn_before=timedelta(days=args.warn_days))
        print(json.dumps(asdict(health), default=str))
        return
    if args.action == "activate":

        def verify(client: Ksef) -> None:
            client.api.limits.get_context_limits()
            if args.queue is None:
                return
            with open_queue(args.queue) as store:
                worker = client.invoices.offline(store, namespace=profile.name)
                after = None
                while page := worker.pending(after=after):
                    for item in page:
                        reference = item.progress.session_reference
                        if reference is not None:
                            client.api.sessions.get_session_status(reference)
                    after = page[-1].due_at, page[-1].progress.invoice_hash

        selection = selector.activate(
            args.name,
            expected_generation=args.expected_generation,
            subject_identifier_type=(
                "certificateFingerprint" if args.fingerprint else "certificateSubject"
            ),
            password=read_password(args.name),
            verify=verify,
        )
        print(json.dumps(asdict(selection)))
        return

    if (args.after_due_at is None) != (args.after_hash is None):
        parser.error("--after-due-at and --after-hash must be provided together")
    after = (args.after_due_at, args.after_hash) if args.after_due_at is not None else None
    rows, failures = [], []
    with open_queue(args.queue) as store:
        queue = OfflineInvoiceQueue(
            store,
            options=profile.to_options(),
            context_type=profile.context_type,
            context_value=profile.context_value,
            namespace=profile.name,
        )
        page = queue.pending(limit=args.limit, after=after)
        if page:
            with selector.session(password_for=read_password) as client:
                worker = client.invoices.offline(store, namespace=profile.name)
                rows, failures = worker.advance_batch(page, submit_immediately=True)

    cursor = (
        {"due_at": page[-1].due_at, "invoice_hash": page[-1].progress.invoice_hash}
        if len(page) == args.limit
        else None
    )
    print(
        json.dumps(
            {
                "invoices": [
                    {
                        "invoice_hash": row.progress.invoice_hash,
                        "status": row.progress.status.value,
                        "due_at": row.due_at,
                    }
                    for row in rows
                ],
                "failures": [asdict(failure) for failure in failures],
                "next_cursor": cursor,
            }
        )
    )


if __name__ == "__main__":
    main()
