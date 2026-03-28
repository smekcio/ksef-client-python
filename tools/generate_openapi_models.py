import argparse
import difflib
import keyword
import re
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.openapi_spec import (
    DEFAULT_KSEF_OPENAPI_FALLBACK_PATH,
    OpenApiSpecError,
    load_openapi_document,
    parse_openapi_json,
    write_openapi_snapshot,
)


def _to_snake_case(name: str) -> str:
    normalized = re.sub(r"[^0-9A-Za-z]+", "_", name)
    normalized = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", normalized)
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized)
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized.lower() or name.lower()


def _sanitize_field_name(name: str, used: set[str]) -> str:
    name = _to_snake_case(name)
    if keyword.iskeyword(name):
        name = f"{name}_"
    base = name
    index = 1
    while name in used:
        name = f"{base}_{index}"
        index += 1
    used.add(name)
    return name


def _enum_member_name(value: str, used: set[str]) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", value).upper()
    if not name or name[0].isdigit():
        name = f"VALUE_{name}"
    base = name
    index = 1
    while name in used:
        name = f"{base}_{index}"
        index += 1
    used.add(name)
    return name


def _ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def _schema_type(schema: dict) -> str:
    if "oneOf" in schema:
        items = schema.get("oneOf") or []
        if len(items) == 1:
            return _schema_type(items[0])
        return "Any"
    if "anyOf" in schema:
        items = schema.get("anyOf") or []
        if len(items) == 1:
            return _schema_type(items[0])
        return "Any"
    if "allOf" in schema:
        items = schema.get("allOf") or []
        if len(items) == 1:
            return _schema_type(items[0])
        return "Any"
    if "$ref" in schema:
        return _ref_name(schema["$ref"])
    schema_type = schema.get("type")
    if schema_type == "array":
        item_type = _schema_type(schema.get("items", {}))
        return f"list[{item_type}]"
    if schema_type == "object":
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            value_type = _schema_type(additional)
            if additional.get("nullable"):
                value_type = _optional_type(value_type)
            return f"dict[str, {value_type}]"
        return "dict[str, Any]"
    if schema_type == "integer":
        return "int"
    if schema_type == "number":
        return "float"
    if schema_type == "boolean":
        return "bool"
    if schema_type == "string":
        return "str"
    return "Any"


def _optional_type(type_name: str) -> str:
    return f"Optional[{type_name}]"


def _generate_alias(name: str, schema: dict) -> list[str]:
    schema_type = schema.get("type")
    if schema_type == "integer":
        target = "int"
    elif schema_type == "number":
        target = "float"
    elif schema_type == "boolean":
        target = "bool"
    else:
        target = "str"
    return [f"{name}: TypeAlias = {target}"]


def _generate_enum(name: str, schema: dict) -> list[str]:
    lines = [f"class {name}(OpenApiEnum):"]
    used: set[str] = set()
    for value in schema.get("enum", []):
        value_str = str(value)
        member = _enum_member_name(value_str, used)
        lines.append(f'    {member} = "{value_str}"')
    if len(lines) == 1:
        lines.append("    pass")
    return lines


def _generate_object(name: str, schema: dict) -> list[str]:
    required = set(schema.get("required", []))
    props = schema.get("properties") or {}
    lines = ["@dataclass(frozen=True)", f"class {name}(OpenApiModel):"]
    used_names: set[str] = set()
    if not props:
        lines.append("    pass")
        return lines
    prepared = []
    for prop_name, prop_schema in props.items():
        field_name = _sanitize_field_name(prop_name, used_names)
        type_name = _schema_type(prop_schema)
        is_required = prop_name in required
        is_nullable = bool(prop_schema.get("nullable"))
        if is_nullable or not is_required:
            type_name = _optional_type(type_name)
        metadata = None
        if field_name != prop_name:
            metadata = f'metadata={{"json_key": "{prop_name}"}}'
        prepared.append((is_required, field_name, type_name, metadata))
    prepared.sort(key=lambda item: (not item[0], item[1]))
    for is_required, field_name, type_name, metadata in prepared:
        if not is_required:
            if metadata:
                default = f"field(default=None, {metadata})"
                lines.append(f"    {field_name}: {type_name} = {default}")
            else:
                lines.append(f"    {field_name}: {type_name} = None")
        else:
            if metadata:
                lines.append(f"    {field_name}: {type_name} = field({metadata})")
            else:
                lines.append(f"    {field_name}: {type_name}")
    return lines


def render_models(data: dict[str, Any]) -> str:
    schemas = data.get("components", {}).get("schemas", {})
    alias_names = []
    enum_names = []
    object_names = []
    for name, schema in schemas.items():
        schema_type = schema.get("type")
        if schema_type == "object":
            object_names.append(name)
        elif "enum" in schema:
            enum_names.append(name)
        else:
            alias_names.append(name)

    lines: list[str] = [
        "# ruff: noqa",
        "# Generated from the official KSeF OpenAPI spec. Do not edit manually.",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass, field, fields",
        "from enum import Enum",
        "import sys",
        "from typing import Any, Optional, TypeAlias, TypeVar, cast",
        "from typing import get_args, get_origin, get_type_hints",
        "",
        "JsonValue: TypeAlias = Any",
        "",
        'T = TypeVar("T", bound="OpenApiModel")',
        "_TYPE_CACHE: dict[type, dict[str, Any]] = {}",
        "",
        "class OpenApiEnum(str, Enum):",
        "    @classmethod",
        "    def _missing_(cls, value: object) -> OpenApiEnum:",
        "        if not isinstance(value, str):",
        '            raise ValueError(f"{value!r} is not a valid {cls.__name__}")',
        "        existing = cast(OpenApiEnum | None, cls._value2member_map_.get(value))",
        "        if existing is not None:",
        "            return existing",
        "        pseudo_member = str.__new__(cls, value)",
        '        pseudo_member._name_ = f"UNKNOWN__{len(cls._value2member_map_) + 1}"',
        "        pseudo_member._value_ = value",
        "        cls._value2member_map_[value] = pseudo_member",
        "        return pseudo_member",
        "",
        "def _get_type_map(cls: type) -> dict[str, Any]:",
        "    cached = _TYPE_CACHE.get(cls)",
        "    if cached is not None:",
        "        return cached",
        "    module = sys.modules[cls.__module__]",
        "    hints = get_type_hints(cls, globalns=vars(module), localns=vars(module))",
        "    _TYPE_CACHE[cls] = hints",
        "    return hints",
        "",
        "def _convert_value(type_hint: Any, value: Any) -> Any:",
        "    if value is None:",
        "        return None",
        "    origin = get_origin(type_hint)",
        "    if origin is list:",
        "        item_type = get_args(type_hint)[0] if get_args(type_hint) else Any",
        "        return [_convert_value(item_type, item) for item in value]",
        "    if origin is dict:",
        "        key_type, value_type = (get_args(type_hint) + (Any, Any))[:2]",
        "        return {",
        "            _convert_value(key_type, key): _convert_value(value_type, item)",
        "            for key, item in value.items()",
        "        }",
        "    if origin is not None:",
        "        args = [arg for arg in get_args(type_hint) if arg is not type(None)]",
        "        if args:",
        "            return _convert_value(args[0], value)",
        "    if isinstance(type_hint, type) and issubclass(type_hint, Enum):",
        "        return type_hint(value)",
        "    if isinstance(type_hint, type) and issubclass(type_hint, OpenApiModel):",
        "        if isinstance(value, dict):",
        "            return type_hint.from_dict(value)",
        "    return value",
        "",
        "def _serialize_value(value: Any) -> Any:",
        "    if isinstance(value, Enum):",
        "        return value.value",
        "    if isinstance(value, OpenApiModel):",
        "        return value.to_dict()",
        "    if isinstance(value, list):",
        "        return [_serialize_value(item) for item in value]",
        "    if isinstance(value, dict):",
        "        return {key: _serialize_value(item) for key, item in value.items()}",
        "    return value",
        "",
        "class OpenApiModel:",
        "    @classmethod",
        "    def from_dict(cls: type[T], data: dict[str, Any]) -> T:",
        "        if data is None:",
        '            raise ValueError("data is None")',
        "        type_map = _get_type_map(cls)",
        "        kwargs: dict[str, Any] = {}",
        "        for model_field in fields(cls):  # type: ignore",
        '            json_key = model_field.metadata.get("json_key", model_field.name)',
        "            if json_key in data:",
        "                type_hint = type_map.get(model_field.name, Any)",
        "                kwargs[model_field.name] = _convert_value(type_hint, data[json_key])",
        "        return cls(**kwargs)",
        "",
        "    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:",
        "        result: dict[str, Any] = {}",
        "        for model_field in fields(self):  # type: ignore",
        '            json_key = model_field.metadata.get("json_key", model_field.name)',
        "            value = getattr(self, model_field.name)",
        "            if omit_none and value is None:",
        "                continue",
        "            result[json_key] = _serialize_value(value)",
        "        return result",
        "",
    ]

    for name in sorted(enum_names):
        lines.extend(_generate_enum(name, schemas[name]))
        lines.append("")

    for name in sorted(alias_names):
        lines.extend(_generate_alias(name, schemas[name]))
        lines.append("")

    for name in sorted(object_names):
        lines.extend(_generate_object(name, schemas[name]))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def generate_models(
    input_path: Path | None,
    output_path: Path,
    *,
    snapshot_path: Path = DEFAULT_KSEF_OPENAPI_FALLBACK_PATH,
    allow_fallback: bool = True,
) -> None:
    document = load_openapi_document(
        input_path=input_path,
        fallback_path=snapshot_path,
        allow_fallback=allow_fallback,
    )
    data = parse_openapi_json(document)
    rendered = render_models(data)
    output_path.write_text(rendered, encoding="utf-8", newline="\n")
    if input_path is None and not document.used_fallback:
        write_openapi_snapshot(document.text, snapshot_path=snapshot_path)


def check_generated_models(
    input_path: Path | None,
    output_path: Path,
    *,
    allow_fallback: bool = True,
) -> str | None:
    document = load_openapi_document(input_path=input_path, allow_fallback=allow_fallback)
    data = parse_openapi_json(document)
    rendered = render_models(data)
    try:
        existing = output_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OpenApiSpecError(
            f"Failed to read generated models from {output_path}: {exc}"
        ) from exc
    if existing == rendered:
        return None
    diff = difflib.unified_diff(
        existing.splitlines(),
        rendered.splitlines(),
        fromfile=str(output_path),
        tofile="generated-openapi-models",
        lineterm="",
    )
    return "\n".join(diff) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        help="Optional path to a local OpenAPI JSON file. Defaults to the official KSeF endpoint.",
    )
    parser.add_argument(
        "--output",
        default=Path("src/ksef_client/openapi_models.py"),
        type=Path,
        help="Path to output Python file.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the generated content differs from --output instead of writing the file.",
    )
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="Require the live OpenAPI spec when --input is not provided.",
    )
    args = parser.parse_args()
    try:
        if args.check:
            diff = check_generated_models(
                args.input,
                args.output,
                allow_fallback=not args.no_fallback,
            )
            if diff is not None:
                print(diff, end="")
                raise SystemExit(
                    "Generated models are out of date. "
                    "Run tools/generate_openapi_models.py and commit the result."
                )
            return
        generate_models(
            args.input,
            args.output,
            allow_fallback=not args.no_fallback,
        )
    except OpenApiSpecError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
