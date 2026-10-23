from __future__ import annotations

import os
import sys
from pathlib import Path

SRC_PATH = Path(__file__).resolve().parents[1] / "src"
if os.environ.get("KSEF_TEST_INSTALLED") == "1":
    import ksef_client

    imported = Path(ksef_client.__file__).resolve()
    if SRC_PATH.resolve() in imported.parents:
        raise RuntimeError("E2E must import the installed wheel, not repository src")
    from tools.release_artifacts import verify_installed_wheel

    wheel_path = os.environ.get("KSEF_TEST_WHEEL")
    if not wheel_path:
        raise RuntimeError("Installed wheel mode requires KSEF_TEST_WHEEL")
    verify_installed_wheel(Path(wheel_path))
elif str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))
