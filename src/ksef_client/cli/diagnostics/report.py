from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DiagnosticReport:
    status: str
    checks: list[dict[str, str]] = field(default_factory=list)
