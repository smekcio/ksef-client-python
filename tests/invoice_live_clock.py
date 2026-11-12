"""Virtual time for synchronous live-helper contract tests; no real sleeping."""

from __future__ import annotations

import time
from contextlib import contextmanager

from ksef_client.rate_limiting import RequestControl


class VirtualClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(float(seconds), 0.000001)


@contextmanager
def virtual_time(monkeypatch):
    clock = VirtualClock()
    original_check = RequestControl.check
    original_remaining = RequestControl.remaining
    with monkeypatch.context() as patch:
        patch.setattr(time, "monotonic", clock)
        patch.setattr(time, "sleep", clock.sleep)
        patch.setattr(
            RequestControl, "check", lambda self, **kwargs: original_check(self, clock=clock)
        )
        patch.setattr(
            RequestControl,
            "remaining",
            lambda self, **kwargs: original_remaining(self, clock=clock),
        )
        yield clock
