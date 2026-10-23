"""Live TEST cursor restart through a fresh interpreter using the installed SDK."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from functools import partial

import pytest

from ksef_client import KsefClient, KsefClientOptions
from ksef_client import models as m
from ksef_client.services import OnlineSessionWorkflow
from tests.test_e2e_token_flows import (
    FORM_CODE,
    _authenticate_access_token,
    _build_invoice_xml,
    _ensure_e2e_enabled,
    _load_test_token_config,
    _poll_for_ksef_number,
    _select_certificate,
    _with_rate_limit_retry,
)

pytestmark = pytest.mark.e2e

# JSON credentials and cursors are passed through stdin, never process arguments.
_CHILD = """
import json, sys
from pathlib import Path
import ksef_client
from ksef_client import KsefClient, KsefClientOptions, models as m
request = json.load(sys.stdin)
if request["installed"]:
    assert "site-packages" in str(Path(ksef_client.__file__).resolve())
with KsefClient(KsefClientOptions(base_url=request["url"]), access_token=request["token"]) as c:
    search = c.invoices.search_invoice_metadata(m.InvoiceQueryFilters.from_dict(request["filters"]),
        context_key=request["context"], page_size=10)
    numbers = [item.ksef_number for item in search.items(request["cursor"])]
print(json.dumps(numbers))
"""


def test_e2e_test_environment_cursor_restart(tmp_path) -> None:
    _ensure_e2e_enabled()
    config = _load_test_token_config()
    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    options = KsefClientOptions(base_url=config.base_url)
    with KsefClient(options) as client:
        certs = _with_rate_limit_retry(client.security.get_public_key_certificates)
        token = _authenticate_access_token(
            client, config=config, token_cert=_select_certificate(certs, "KsefTokenEncryption")
        )
        session = OnlineSessionWorkflow(client.sessions).open_session(
            form_code=FORM_CODE,
            public_certificate=_select_certificate(certs, "SymmetricKeyEncryption"),
            access_token=token,
        )
        expected = set()
        try:
            # Eleven distinct invoices guarantee a second page at the minimum page size.
            for _ in range(11):
                sent = session.send_invoice(
                    _build_invoice_xml(seller_nip=config.context_value, environment_name="test"),
                    access_token=token,
                )
                expected.add(
                    _poll_for_ksef_number(
                        client,
                        session_reference_number=session.reference_number,
                        invoice_reference_number=sent.reference_number,
                        access_token=token,
                    )
                )
            session.close(access_token=token)
            request = m.InvoiceQueryFilters(
                subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
                date_range=m.InvoiceQueryDateRange(
                    date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                    from_=start.isoformat(),
                    # A fresh poll freezes now; storage may finish after session close.
                    to=None,
                    restrict_to_permanent_storage_hwm_date=True,
                ),
            )
            context = f"{config.context_type}:{config.context_value}"
            # Wait for the stable HWM to include the submissions; do not resubmit them.
            deadline = time.monotonic() + 300
            while True:
                search = client.invoices.search_invoice_metadata(
                    request, context_key=context, page_size=10, access_token=token
                )
                rows: list[m.InvoiceMetadata] = _with_rate_limit_retry(partial(list, search))
                numbers = {row.ksef_number for row in rows}
                if expected <= numbers:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("Submitted invoices did not reach metadata HWM")
                time.sleep(5)
            first = _with_rate_limit_retry(search.page)
            assert first.next_cursor is not None
            parent_remaining = [row.ksef_number for row in search.items(first.next_cursor)]
            payload = {
                "url": config.base_url,
                "token": token,
                "context": context,
                "filters": request.to_dict(),
                "cursor": first.next_cursor,
                "installed": os.environ.get("KSEF_TEST_INSTALLED") == "1",
            }
            env = dict(os.environ)
            if payload["installed"]:
                env.pop("PYTHONPATH", None)
            else:
                # Local developer execution still uses the source checkout explicitly.
                from pathlib import Path

                env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            process = subprocess.run(
                [sys.executable, "-c", _CHILD],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                cwd=tmp_path,
                env=env,
                timeout=180,
                check=False,
            )
            assert process.returncode == 0, "Cursor child process failed (output withheld)"
            child_remaining = json.loads(process.stdout)
            assert child_remaining == parent_remaining
            complete = [row.ksef_number for row in first.items] + child_remaining
            assert len(complete) == len(set(complete))
            assert expected <= set(complete)
        finally:
            with suppress(Exception):
                session.close(access_token=token)
