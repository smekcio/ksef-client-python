"""Pokrycie klienta Latarni względem specyfikacji OpenAPI.

Test był dotąd **zawsze pomijany**: szukał ``../ksef-latarnia/open-api.json``
(checkout monorepo, którego w tym repozytorium nie ma) i wywoływał ``skipTest``,
więc brak implementacji endpointu Latarni przechodził przez CI niezauważony.
Teraz test korzysta z **wbudowanego, minimalnego snapshotu** kontraktu Latarni
(``LATARNIA_OPENAPI_SNAPSHOT``), a pełną specyfikację z checkoutu monorepo
(``LATARNIA_EXTERNAL_SPEC_PATH``) wykorzystuje wtedy, gdy jest dostępna — dzięki
temu działa też w monorepo, ale nie jest już od niego zależny.

Pochodzenie snapshotu: publiczne, nieautoryzowane endpointy Latarni KSeF
udokumentowane w ``docs/api/lighthouse.md`` (``GET /status``, ``GET /messages``)
i potwierdzone na żywym API — ``GET https://api-latarnia.ksef.mf.gov.pl/status``
odpowiada ``{"status":"AVAILABLE"}``. Snapshot jest celowo minimalny: pilnuje
kontraktu, którego używa klient, a nie całej zewnętrznej specyfikacji (pełny
zestaw operacji wymaga ``open-api.json`` z repozytorium Latarni). Test nie
wykonuje żadnych żądań sieciowych.
"""

from __future__ import annotations

import ast
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse

#: Pełna specyfikacja Latarni z checkoutu monorepo (``ksef-python/ksef-latarnia``).
#: Gdy plik istnieje, ma pierwszeństwo przed wbudowanym snapshotem.
LATARNIA_EXTERNAL_SPEC_PATH = (
    Path(__file__).resolve().parents[2] / "ksef-latarnia" / "open-api.json"
)

#: Minimalny, samowystarczalny snapshot operacji Latarni konsumowanych przez klienta.
LATARNIA_OPENAPI_SNAPSHOT: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {
        "title": "KSeF Latarnia API (minimalny snapshot operacji klienta)",
        "version": "1.0.0",
    },
    "paths": {
        "/status": {"get": {"summary": "Status środowisk KSeF"}},
        "/messages": {"get": {"summary": "Komunikaty opublikowane przez Latarnię"}},
    },
}

#: Operacje udokumentowane w ``docs/api/lighthouse.md``; snapshot nie może ich zgubić.
DOCUMENTED_LIGHTHOUSE_OPERATIONS = {("GET", "/status"), ("GET", "/messages")}


def _normalize_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _render_path(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _render_path(node.left)
        right = _render_path(node.right)
        if left is None or right is None:
            return None
        return left + right
    return None


def _normalize_request_path(path: str) -> str | None:
    stripped = path.strip()
    if not stripped:
        return None
    if stripped.startswith("http://") or stripped.startswith("https://"):
        parsed = urlparse(stripped)
        return parsed.path or "/"
    if stripped.startswith("/"):
        return stripped.split("?", 1)[0].split("#", 1)[0]
    slash_index = stripped.find("/")
    if slash_index >= 0:
        return stripped[slash_index:].split("?", 1)[0].split("#", 1)[0]
    return None


def _extract_python_lighthouse_operations() -> set[tuple[str, str]]:
    project_root = Path(__file__).resolve().parents[1]
    py_file = project_root / "src" / "ksef_client" / "clients" / "lighthouse.py"
    ops: set[tuple[str, str]] = set()

    tree = ast.parse(py_file.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "_request_json":
            continue
        if len(node.args) < 2:
            continue

        method = _const_str(node.args[0])
        path_expr = _render_path(node.args[1])
        if not method or not path_expr:
            continue
        normalized_path = _normalize_request_path(path_expr)
        if not normalized_path:
            continue
        ops.add((method.upper(), _normalize_path(normalized_path)))

    return ops


def _extract_openapi_lighthouse_operations(spec: dict[str, Any]) -> set[tuple[str, str]]:
    ops: set[tuple[str, str]] = set()
    for path, methods in spec["paths"].items():
        for method in methods:
            method_upper = method.upper()
            if method_upper in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                ops.add((method_upper, _normalize_path(path)))
    return ops


def _load_latarnia_spec() -> tuple[dict[str, Any], str]:
    """Zwraca ``(specyfikacja, źródło)``: pełny checkout monorepo albo snapshot.

    Brak zewnętrznego checkoutu nie jest już cichym pominięciem — test wykonuje
    się na wbudowanym snapshocie.
    """
    if LATARNIA_EXTERNAL_SPEC_PATH.exists():
        loaded: dict[str, Any] = json.loads(
            LATARNIA_EXTERNAL_SPEC_PATH.read_text(encoding="utf-8")
        )
        return loaded, str(LATARNIA_EXTERNAL_SPEC_PATH)
    return LATARNIA_OPENAPI_SNAPSHOT, "wbudowany snapshot LATARNIA_OPENAPI_SNAPSHOT"


class LighthouseOpenApiCoverageTests(unittest.TestCase):
    def test_normalize_request_path(self) -> None:
        self.assertEqual(
            _normalize_request_path("https://api-latarnia-test.ksef.mf.gov.pl/messages"),
            "/messages",
        )
        self.assertEqual(
            _normalize_request_path("https://example.com/api/v1/lighthouse/status?x=1"),
            "/api/v1/lighthouse/status",
        )
        self.assertEqual(
            _normalize_request_path("/status?expand=true"),
            "/status",
        )
        self.assertEqual(_normalize_request_path("{}/messages"), "/messages")
        self.assertIsNone(_normalize_request_path("status"))

    def test_snapshot_contains_documented_lighthouse_operations(self) -> None:
        """Snapshot nie może zostać wyczyszczony, żeby "naprawić" test pokrycia."""
        spec_ops = _extract_openapi_lighthouse_operations(LATARNIA_OPENAPI_SNAPSHOT)
        self.assertTrue(
            DOCUMENTED_LIGHTHOUSE_OPERATIONS.issubset(spec_ops),
            f"snapshot nie zawiera udokumentowanych operacji: {spec_ops}",
        )
        self.assertLess(len(spec_ops), 10, "snapshot ma pozostać minimalny")

    def test_python_lighthouse_client_covers_openapi_spec(self) -> None:
        spec, source = _load_latarnia_spec()
        spec_ops = _extract_openapi_lighthouse_operations(spec)
        py_ops = _extract_python_lighthouse_operations()

        self.assertTrue(spec_ops, f"specyfikacja bez operacji ({source})")
        self.assertTrue(py_ops, "nie udało się wyekstrahować operacji klienta Latarni")
        missing = sorted(spec_ops - py_ops)
        extra = sorted(py_ops - spec_ops)

        self.assertFalse(missing, f"Missing Lighthouse OpenAPI operations ({source}): {missing}")
        self.assertFalse(extra, f"Extra Lighthouse operations not in spec ({source}): {extra}")

    def test_drift_between_spec_and_client_is_detected(self) -> None:
        """Kontrola negatywna: operacja z specyfikacji bez pokrycia musi być widoczna."""
        drifted_spec: dict[str, Any] = {
            "paths": {"/status": {"get": {}}, "/messages/archive": {"get": {}}}
        }
        drift = sorted(
            _extract_openapi_lighthouse_operations(drifted_spec)
            - _extract_python_lighthouse_operations()
        )
        self.assertEqual(drift, [("GET", "/messages/archive")])

    def test_external_monorepo_spec_takes_precedence(self) -> None:
        """Gdy checkout ``ksef-latarnia`` jest dostępny, używana jest pełna specyfikacja."""
        external_spec = {"openapi": "3.0.3", "paths": {"/status": {"get": {}}}}
        with tempfile.TemporaryDirectory() as tmp_dir:
            external_path = Path(tmp_dir) / "open-api.json"
            external_path.write_text(json.dumps(external_spec), encoding="utf-8")
            with patch.object(
                sys.modules[__name__], "LATARNIA_EXTERNAL_SPEC_PATH", external_path
            ):
                spec, source = _load_latarnia_spec()

        self.assertEqual(source, str(external_path))
        self.assertEqual(spec["paths"], external_spec["paths"])
        # Ze specyfikacją zewnętrzną dryf klienta (np. usunięty ``GET /status``)
        # jest widoczny w asercjach testu pokrycia.
        self.assertEqual(_extract_openapi_lighthouse_operations(spec), {("GET", "/status")})


if __name__ == "__main__":
    unittest.main()
