from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    VALIDATION_ERROR = 2
    AUTH_ERROR = 3
    RETRY_EXHAUSTED = 4
    API_ERROR = 5
    CONFIG_ERROR = 6
    CIRCUIT_OPEN = 7
    IO_ERROR = 8
