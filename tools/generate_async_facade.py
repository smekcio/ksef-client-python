"""Generate explicit async facade methods from the synchronous facade; --check in CI/tests."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = {
    name: "Async" + name
    for name in (
        "Ksef",
        "KsefClient",
        "AuthenticatedClient",
        "Operation",
        "AuthenticationOperation",
        "Session",
        "Invoices",
        "Exports",
        "Permissions",
        "Certificates",
        "OnlineSessionWorkflow",
        "BatchSessionWorkflow",
        "ExportOperation",
    )
}
ASYNC = {
    "_redeem",
    "close",
    "__enter__",
    "__exit__",
    "send_invoice",
    "upload_parts",
    "download",
    "start",
    "begin_auth",
    "connect",
    "_certificate",
    "online_session",
    "batch_session",
    "send_enrollment",
    "get_limits",
    "get_enrollment_data",
    "query_certificates",
    "retrieve_certificate",
    "revoke_certificate",
    "grant_authorization",
    "grant_entity",
    "grant_eu_entity",
    "grant_eu_entity_admin",
    "grant_indirect",
    "grant_person",
    "grant_subunit",
    "revoke_authorization",
    "revoke_common_permission",
}


class Convert(ast.NodeTransformer):
    active = False
    callback = False

    def visit_Name(self, node):
        node.id = NAMES.get(node.id, node.id)
        return node

    def visit_ClassDef(self, node):
        node.name = NAMES.get(node.name, node.name)
        return self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            alias.name = NAMES.get(alias.name, alias.name)
        return node

    def visit_FunctionDef(self, node):
        before = self.active
        self.active = node.name in ASYNC
        self.generic_visit(node)
        if self.active:
            node = ast.AsyncFunctionDef(**{name: getattr(node, name) for name in node._fields})
            node.name = {"__enter__": "__aenter__", "__exit__": "__aexit__"}.get(
                node.name, node.name
            )
        self.active = before
        return node

    def visit_With(self, node):
        self.generic_visit(node)
        if self.active and any(isinstance(item.context_expr, ast.Await) for item in node.items):
            return ast.AsyncWith(items=node.items, body=node.body, type_comment=node.type_comment)
        return node

    def visit_Lambda(self, node):
        if ast.dump(node.body) == ast.dump(ast.parse("status.upo", mode="eval").body):
            return ast.Name(id="_upo_result", ctx=ast.Load())
        # Fetch callbacks return awaitables; lambda bodies cannot contain await.
        before, self.active = self.active, False
        previous_callback, self.callback = self.callback, True
        self.generic_visit(node)
        self.active = before
        self.callback = previous_callback
        return node

    def visit_Call(self, node):
        path = ast.unparse(node.func)
        self.generic_visit(node)
        if self.active and path == "auth_payload":
            return ast.Await(
                value=ast.Call(
                    func=ast.parse("asyncio.to_thread", mode="eval").body,
                    args=[node.func, *node.args],
                    keywords=node.keywords,
                )
            )
        if self.active and path == "self.handle.upload_parts":
            return ast.Await(
                value=ast.Call(
                    func=ast.Name(id="_upload_batch_parts", ctx=ast.Load()),
                    args=[
                        ast.parse("self.handle", mode="eval").body,
                        ast.parse("self.owner.api.http_client", mode="eval").body,
                    ],
                    keywords=node.keywords,
                )
            )
        if path == "cls.from_auth_result":
            return node
        requires_await = (
            path.startswith(
                (
                    "api.auth.",
                    "api.security.",
                    "self.api.auth.",
                    "self.owner.api.",
                    "self.api.security.",
                )
            )
            or path.endswith(".open_session")
            or path
            in {
                "self.handle.send_invoice",
                "self.handle.upload_parts",
                "self.handle.close",
                "self.owner._certificate",
                "self._certificate",
                "cls.begin_auth",
                "operation.wait",
                "self.close",
                "api.close",
                "self.api.close",
            }
        )
        if requires_await and not self.active and not self.callback:
            raise ValueError(f"Unmapped asynchronous I/O call: {path}")
        if self.active and requires_await:
            if path in {"api.close", "self.api.close"}:
                node.func.attr = "aclose"
            return ast.Await(value=node)
        return node

    def visit_Subscript(self, node):
        self.generic_visit(node)
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "Callable"
            and isinstance(node.slice, ast.Tuple)
            and ast.unparse(node.slice.elts[0]) == "[m.TokenInfo]"
        ):
            node.slice.elts[1] = ast.parse("Awaitable[None] | None", mode="eval").body
        return node


def generate() -> str:
    tree = ast.parse((ROOT / "src/ksef_client/facade.py").read_text(encoding="utf-8"))
    classes: list[ast.stmt] = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name
        in {
            "AuthenticationOperation",
            "Session",
            "Invoices",
            "Exports",
            "Ksef",
            "Permissions",
            "Certificates",
        }
    ]
    converted = ast.fix_missing_locations(
        Convert().visit(ast.Module(body=classes, type_ignores=[]))
    )
    code = ast.unparse(converted)
    header = '''"""Generated by tools/generate_async_facade.py. Edit facade.py instead."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from . import models as m
from .client import AsyncAuthenticatedClient, AsyncKsefClient
from .config import KsefClientOptions
from .facade import (
    FA3,
    Credentials,
    TokenCredentials,
    XadesCredentials,
    auth_payload,
    connection_options,
    safe_options,
    validate_auth_state,
)
from .operations import (
    AsyncOperation,
    KsefOperationError,
    OperationState,
    environment_key,
    validate_wait,
)
from .profiles import Profile, ProfileStore
from .request_control import request_control
from .services.crypto import build_encryption_data
from .services.sessions import AsyncBatchSessionHandle, BatchSessionState, OnlineSessionState
from .services.workflows import (
    AsyncBatchSessionWorkflow,
    AsyncBatchUploadHelper,
    AsyncOnlineSessionWorkflow,
    AuthResult,
)
from .token_manager import DEFAULT_REFRESH_MARGIN_SECONDS

if TYPE_CHECKING:
    from .streaming_export import AsyncExportOperation


async def _upo_result(status: Any) -> m.UpoResponse:
    return status.upo


async def _upload_batch_parts(
    handle: AsyncBatchSessionHandle,
    http: Any,
    *,
    parallelism: int,
    skip_ordinals: set[int],
    progress_callback: Callable[[int], None],
) -> None:
    configured = replace(handle, _uploader=AsyncBatchUploadHelper(http, parallelism=parallelism))
    await configured.upload_parts(skip_ordinals=skip_ordinals, progress_callback=progress_callback)

'''
    return header + code + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate()
    target = ROOT / "src/ksef_client/async_facade.py"
    if args.check:
        # ast.unparse adds tuple-target parentheses on Python 3.10. Compare
        # syntax trees so the same implementation passes on every supported Python.
        if ast.dump(ast.parse(target.read_text(encoding="utf-8"))) != ast.dump(ast.parse(result)):
            raise SystemExit("Async facade is stale")
    else:
        target.write_text(result, encoding="utf-8")


if __name__ == "__main__":
    main()
