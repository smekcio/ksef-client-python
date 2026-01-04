import ast
import json
import re
import unittest
from pathlib import Path


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


def _extract_python_openapi_operations() -> set[tuple[str, str]]:
    project_root = Path(__file__).resolve().parents[1]
    clients_root = project_root / "src" / "ksef_client" / "clients"
    ops: set[tuple[str, str]] = set()

    for py_file in clients_root.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"_request_json", "_request_bytes", "_request_raw"}:
                continue
            if len(node.args) < 2:
                continue

            method = _const_str(node.args[0])
            path = _render_path(node.args[1])
            if not method or not path or not path.startswith("/"):
                continue
            ops.add((method.upper(), _normalize_path(path)))

    return ops


def _extract_openapi_spec_operations(openapi_path: Path) -> set[tuple[str, str]]:
    spec = json.loads(openapi_path.read_text(encoding="utf-8"))
    ops: set[tuple[str, str]] = set()
    for path, methods in spec["paths"].items():
        for method in methods:
            method_upper = method.upper()
            if method_upper in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                ops.add((method_upper, _normalize_path(path)))
    return ops


class OpenApiCoverageTests(unittest.TestCase):
    def test_python_clients_cover_openapi_spec(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        openapi_path = repo_root / "ksef-docs" / "open-api.json"
        if not openapi_path.exists():
            self.skipTest("open-api.json not found; coverage test requires monorepo layout")

        spec_ops = _extract_openapi_spec_operations(openapi_path)
        py_ops = _extract_python_openapi_operations()
        missing = sorted(spec_ops - py_ops)
        self.assertFalse(missing, f"Missing OpenAPI operations in Python clients: {missing}")


if __name__ == "__main__":
    unittest.main()
