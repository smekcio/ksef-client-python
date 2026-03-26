"""CLI package for ksef-client."""

__all__ = ["app", "app_entrypoint"]


def __getattr__(name: str):
    if name == "app":
        from .bootstrap import get_app

        return get_app()
    if name == "app_entrypoint":
        from .bootstrap import app_entrypoint

        return app_entrypoint
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
