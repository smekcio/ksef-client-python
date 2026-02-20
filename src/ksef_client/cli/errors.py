from __future__ import annotations

from dataclasses import dataclass

from .exit_codes import ExitCode


@dataclass
class CliError(Exception):
    message: str
    code: ExitCode
    hint: str | None = None

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message} Hint: {self.hint}"
        return self.message
