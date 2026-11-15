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
from ksef_client.offline_invoices import SQLiteOfflineInvoiceStore
from ksef_client.profiles import ProfileStore


def read_password(name: str) -> str:
    passwords = json.loads(os.environ["KSEF_XADES_KEY_PASSWORDS"])
    return passwords[name]


def check_api(client: Ksef) -> None:
    client.api.limits.get_context_limits()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--selector", type=Path, required=True)
    parser.add_argument("--certificates", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    status = actions.add_parser("status")
    status.add_argument("--warn-days", type=int, default=30)
    activate = actions.add_parser("activate")
    activate.add_argument("name")
    activate.add_argument("--expected-generation", type=int, required=True)
    activate.add_argument("--fingerprint", action="store_true")
    run = actions.add_parser("run")
    run.add_argument("--queue", type=Path, required=True)
    run.add_argument("--limit", type=int, default=20, choices=range(1, 101))
    args = parser.parse_args()

    profile = ProfileStore.default().get(args.profile)
    store = FileCertificateStore(args.certificates, require_password=True)
    selector = ProfileCertificates(args.selector, profile, store=store)
    if args.action == "status":
        health = selector.status(warn_before=timedelta(days=args.warn_days))
        print(json.dumps(asdict(health), default=str))
        return
    if args.action == "activate":
        selection = selector.activate(
            args.name,
            expected_generation=args.expected_generation,
            subject_identifier_type=(
                "certificateFingerprint" if args.fingerprint else "certificateSubject"
            ),
            password=read_password(args.name),
            verify=check_api,
        )
        print(json.dumps(asdict(selection)))
        return

    if not args.queue.is_file():
        parser.error("--queue must refer to an existing staged offline queue")
    key = base64.b64decode(os.environ["KSEF_OFFLINE_STATE_KEY"], validate=True)
    with (
        SQLiteOfflineInvoiceStore.open(args.queue, key=key) as queue,
        selector.session(password_for=read_password) as client,
    ):
        worker = client.invoices.offline(queue, namespace=profile.name)
        for item in worker.pending(limit=args.limit):
            row = worker.advance(item.progress.invoice_hash)
            print(json.dumps({"status": row.progress.status.value, "due_at": row.due_at}))


if __name__ == "__main__":
    main()
