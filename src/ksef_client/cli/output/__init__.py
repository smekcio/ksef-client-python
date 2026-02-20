from __future__ import annotations

from ..context import CliContext
from .base import Renderer
from .human import HumanRenderer
from .json import JsonRenderer


def get_renderer(ctx: CliContext) -> Renderer:
    if ctx.json_output:
        return JsonRenderer(started_at=ctx.started_at)
    return HumanRenderer(no_color=ctx.no_color)
