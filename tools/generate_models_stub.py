from __future__ import annotations

import argparse
import ast
import copy
import difflib
import importlib.util
import sys
from pathlib import Path
from typing import TypeVar, cast

DEFAULT_MODELS_PATH = Path("src/ksef_client/models.py")
DEFAULT_OPENAPI_MODELS_PATH = Path("src/ksef_client/openapi_models.py")
DEFAULT_OUTPUT_PATH = Path("src/ksef_client/models.pyi")
T = TypeVar("T", bound=ast.AST)


class _StubAstTransformer(ast.NodeTransformer):
    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id == "Any":
            return ast.copy_location(ast.Name(id="_Any", ctx=node.ctx), node)
        if node.id == "dataclass":
            return ast.copy_location(ast.Name(id="_dataclass", ctx=node.ctx), node)
        if node.id == "Enum":
            return ast.copy_location(ast.Name(id="_Enum", ctx=node.ctx), node)
        return node


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_openapi_exports(
    openapi_models_path: Path,
    *,
    excluded_names: set[str],
) -> list[str]:
    module_name = "_generated_openapi_models"
    spec = importlib.util.spec_from_file_location(module_name, openapi_models_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Failed to load module spec from {openapi_models_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
    return [
        name
        for name in vars(module)
        if not name.startswith("_") and name not in excluded_names
    ]


def _find_literal_assignment(tree: ast.Module, name: str) -> object:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return ast.literal_eval(node.value)
    raise ValueError(f"Missing assignment for {name}")


def _transform_node(node: T) -> T:
    transformed = copy.deepcopy(node)
    transformed = _StubAstTransformer().visit(transformed)
    ast.fix_missing_locations(transformed)
    return transformed


def _indent(lines: list[str], *, prefix: str = "    ") -> list[str]:
    return [f"{prefix}{line}" if line else "" for line in lines]


def _render_function(node: ast.FunctionDef) -> list[str]:
    stub_function = ast.FunctionDef(
        name=node.name,
        args=node.args,
        body=[ast.Expr(value=ast.Constant(Ellipsis))],
        decorator_list=[],
        returns=node.returns,
        type_comment=node.type_comment,
    )
    return ast.unparse(_transform_node(stub_function)).splitlines()


def _is_field_call(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "field"
    )


def _render_class(node: ast.ClassDef) -> list[str]:
    transformed = _transform_node(node)
    lines: list[str] = []

    for decorator in transformed.decorator_list:
        lines.append(f"@{ast.unparse(decorator)}")

    bases = [ast.unparse(base) for base in transformed.bases]
    keywords = [ast.unparse(keyword) for keyword in transformed.keywords]
    parents = ", ".join([*bases, *keywords])
    if parents:
        lines.append(f"class {transformed.name}({parents}):")
    else:
        lines.append(f"class {transformed.name}:")

    body_lines: list[str] = []
    for item in transformed.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            annotation = ast.unparse(item.annotation)
            if item.value is None:
                body_lines.append(f"{item.target.id}: {annotation}")
            else:
                default = "..." if _is_field_call(item.value) else ast.unparse(item.value)
                body_lines.append(f"{item.target.id}: {annotation} = {default}")
            continue

        if (
            isinstance(item, ast.Assign)
            and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
        ):
            body_lines.append(f"{item.targets[0].id} = ...")
            continue

        if isinstance(item, ast.FunctionDef):
            for decorator in item.decorator_list:
                body_lines.append(f"@{ast.unparse(decorator)}")
            body_lines.extend(_render_function(item))
            continue

    if not body_lines:
        body_lines.append("pass")

    lines.extend(_indent(body_lines))
    return lines


def render_models_stub(
    models_path: Path = DEFAULT_MODELS_PATH,
    *,
    openapi_models_path: Path = DEFAULT_OPENAPI_MODELS_PATH,
) -> str:
    source = _read_text(models_path)
    tree = ast.parse(source, filename=str(models_path))

    excluded_names = set(
        cast(set[str], _find_literal_assignment(tree, "_OPENAPI_EXPORT_EXCLUDES"))
    )
    wrapper_exports = list(
        cast(tuple[str, ...], _find_literal_assignment(tree, "_WRAPPER_EXPORTS"))
    )
    wrapper_export_set = set(wrapper_exports)
    wrapper_classes = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name in wrapper_export_set
    }
    missing_wrappers = [name for name in wrapper_exports if name not in wrapper_classes]
    if missing_wrappers:
        raise ValueError(
            f"Missing wrapper class definitions for: {', '.join(missing_wrappers)}"
        )

    openapi_exports = _load_openapi_exports(
        openapi_models_path,
        excluded_names=excluded_names,
    )
    openapi_exports = [name for name in openapi_exports if name not in wrapper_export_set]
    all_exports = list(dict.fromkeys([*openapi_exports, *wrapper_exports]))

    lines = [
        "# ruff: noqa: F401, I001",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass as _dataclass",
        "from enum import Enum as _Enum",
        "from typing import Any as _Any",
        "",
        "from .openapi_models import (",
    ]
    lines.extend([f"    {name}," for name in openapi_exports])
    lines.extend(
        [
            ")",
            "",
        ]
    )

    for index, name in enumerate(wrapper_exports):
        lines.extend(_render_class(wrapper_classes[name]))
        if index != len(wrapper_exports) - 1:
            lines.append("")
            lines.append("")
        else:
            lines.append("")

    lines.append("")
    lines.append("__all__ = [")
    lines.extend([f'    "{name}",' for name in all_exports])
    lines.append("]")
    lines.append("")

    return "\n".join(lines)


def generate_models_stub(
    output_path: Path = DEFAULT_OUTPUT_PATH,
    *,
    models_path: Path = DEFAULT_MODELS_PATH,
    openapi_models_path: Path = DEFAULT_OPENAPI_MODELS_PATH,
) -> None:
    output_path.write_text(
        render_models_stub(models_path, openapi_models_path=openapi_models_path),
        encoding="utf-8",
        newline="\n",
    )


def check_generated_models_stub(
    output_path: Path = DEFAULT_OUTPUT_PATH,
    *,
    models_path: Path = DEFAULT_MODELS_PATH,
    openapi_models_path: Path = DEFAULT_OPENAPI_MODELS_PATH,
) -> str | None:
    rendered = render_models_stub(models_path, openapi_models_path=openapi_models_path)
    try:
        existing = output_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Failed to read generated models stub from {output_path}: {exc}") from exc
    if existing == rendered:
        return None
    diff = difflib.unified_diff(
        existing.splitlines(),
        rendered.splitlines(),
        fromfile=str(output_path),
        tofile="generated-models-stub",
        lineterm="",
    )
    return "\n".join(diff) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--models",
        default=DEFAULT_MODELS_PATH,
        type=Path,
        help="Path to models.py source file.",
    )
    parser.add_argument(
        "--openapi-models",
        default=DEFAULT_OPENAPI_MODELS_PATH,
        type=Path,
        help="Path to generated openapi_models.py source file.",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_PATH,
        type=Path,
        help="Path to output .pyi file.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the generated content differs from --output instead of writing the file.",
    )
    args = parser.parse_args()

    if args.check:
        diff = check_generated_models_stub(
            args.output,
            models_path=args.models,
            openapi_models_path=args.openapi_models,
        )
        if diff is not None:
            print(diff, end="")
            raise SystemExit(
                "Generated models stub is out of date. "
                "Run tools/generate_models_stub.py and commit the result."
            )
        return

    generate_models_stub(
        args.output,
        models_path=args.models,
        openapi_models_path=args.openapi_models,
    )


if __name__ == "__main__":
    main()
