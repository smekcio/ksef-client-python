from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Renderer
from .json import JsonRenderer

if TYPE_CHECKING:
    from ..context import CliContext


def get_renderer(ctx: "CliContext") -> Renderer:
    if ctx.json_output:
        return JsonRenderer(started_at=ctx.started_at)
    from .human import HumanRenderer

    return HumanRenderer(no_color=ctx.no_color)
