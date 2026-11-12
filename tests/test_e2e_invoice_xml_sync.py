from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.invoice_sync_supervisor import (
    LIVE_SCENARIO_SOFT_TIMEOUT,
    LIVE_SCENARIO_TIMEOUT,
    run_phases,
)
from tests.invoice_xml_live_worker import diagnostic
from tests.test_e2e_token_flows import _ensure_e2e_enabled

pytestmark = pytest.mark.e2e


def test_e2e_test_environment_invoice_xml_restart(tmp_path):
    _ensure_e2e_enabled()
    assert sys.platform == "linux", "Live process supervision requires Linux"
    assert os.environ.get("KSEF_TEST_INSTALLED") == "1", "Exact installed wheel required"
    assert os.environ.get("KSEF_TEST_WHEEL"), "Exact wheel path required"
    tmp_path.chmod(0o700)
    state = {
        "since": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "soft_deadline": time.monotonic() + LIVE_SCENARIO_SOFT_TIMEOUT,
    }
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")
    worker = str(Path(__file__).with_name("invoice_xml_live_worker.py"))
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    try:
        run_phases(
            [[sys.executable, "-I", worker, phase] for phase in ("metadata", "xml")],
            cwd=tmp_path,
            env=env,
            timeout=LIVE_SCENARIO_TIMEOUT,
        )
    except Exception:
        # The parent never exposes stderr, tokens, XML or invoice identifiers.
        safe = diagnostic(path=tmp_path / "xml-live-diagnostic.json")
        pytest.fail("XML restart diagnostic: " + json.dumps(safe), pytrace=False)
    assert json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["complete"]
