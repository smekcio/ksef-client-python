"""One TEST scenario: A/H1, process exit, B, incremental metadata synchronization."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.invoice_sync_supervisor import run_phases
from tests.test_e2e_token_flows import _ensure_e2e_enabled

pytestmark = pytest.mark.e2e


def test_e2e_test_environment_invoice_sync_restart(tmp_path):
    _ensure_e2e_enabled()
    assert os.environ.get("KSEF_TEST_INSTALLED") == "1", "Exact installed wheel required"
    assert os.environ.get("KSEF_TEST_WHEEL"), "Exact wheel path required"
    tmp_path.chmod(0o700)
    state = {
        "since": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        "soft_deadline": time.monotonic() + 1740,
    }
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")
    worker = str(Path(__file__).with_name("invoice_sync_live_worker.py"))
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    run_phases(
        [[sys.executable, "-I", worker, phase] for phase in ("bootstrap", "incremental")],
        cwd=tmp_path,
        env=env,
    )
    for phase in ("bootstrap", "incremental"):
        assert json.loads((tmp_path / (phase + "-evidence.json")).read_text())["complete"]
