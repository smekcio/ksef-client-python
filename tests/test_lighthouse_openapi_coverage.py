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


def _extract_path_suffix(path: str) -> str | None:
    if path.startswith("/"):
        return path
    match = re.search(r"(/[^/?#]+)$", path)
    if not match:
        return None
    return match.group(1)


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
        suffix = _extract_path_suffix(path_expr)
        if not suffix:
            continue
        ops.add((method.upper(), _normalize_path(suffix)))

    return ops


def _extract_openapi_lighthouse_operations(openapi_path: Path) -> set[tuple[str, str]]:
    spec = json.loads(openapi_path.read_text(encoding="utf-8"))
    ops: set[tuple[str, str]] = set()
    for path, methods in spec["paths"].items():
        for method in methods:
            method_upper = method.upper()
            if method_upper in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                ops.add((method_upper, _normalize_path(path)))
    return ops


class LighthouseOpenApiCoverageTests(unittest.TestCase):
    def test_python_lighthouse_client_covers_openapi_spec(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        openapi_path = repo_root / "ksef-latarnia" / "open-api.json"
        if not openapi_path.exists():
            self.skipTest("ksef-latarnia/open-api.json not found; coverage test requires monorepo")

        spec_ops = _extract_openapi_lighthouse_operations(openapi_path)
        py_ops = _extract_python_lighthouse_operations()

        missing = sorted(spec_ops - py_ops)
        extra = sorted(py_ops - spec_ops)

        self.assertFalse(missing, f"Missing Lighthouse OpenAPI operations: {missing}")
        self.assertFalse(extra, f"Extra Lighthouse operations not in spec: {extra}")


if __name__ == "__main__":
    unittest.main()
