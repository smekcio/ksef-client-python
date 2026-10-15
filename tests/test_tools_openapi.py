from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest
from tools import check_coverage as coverage_tool
from tools import generate_openapi_models as generator
from tools import openapi_spec


class _DummyHeaders:
    @staticmethod
    def get_content_charset() -> str:
        return "utf-8"


class _DummyResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload.encode("utf-8")
        self.headers = _DummyHeaders()

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _DummyResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)


def _minimal_openapi() -> dict[str, object]:
    return {
        "openapi": "3.0.0",
        "paths": {
            "/invoices/query/metadata": {
                "post": {
                    "responses": {
                        "200": {"description": "ok"},
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Example": {
                    "type": "object",
                    "required": ["referenceNumber"],
                    "properties": {
                        "referenceNumber": {"type": "string"},
                        "isActive": {"type": "boolean"},
                    },
                }
            }
        },
    }


#: Payloady z audytu: każdy z nich domyka literał i wstawia własny kod do
#: generowanego `openapi_models.py`, który wykonuje się przy imporcie artefaktu.
HOSTILE_ENUM_VALUE = 'x"\nimport sys; sys.stdout.write("PWN-A-ENUM\\n")\nY="'
HOSTILE_SCHEMA_NAME = (
    'Evil(OpenApiModel): pass\nimport sys; sys.stdout.write("PWN-B-CLASS\\n")\nclass Q'
)
HOSTILE_PROPERTY_NAME = (
    'p"}), __import__("sys").stdout.write("PWN-C-PROPNAME\\n")'
    ' or field(default=None, metadata={"json_key": "y'
)


def _schemas_openapi(schemas: dict[str, object]) -> dict[str, object]:
    return {"openapi": "3.0.0", "components": {"schemas": schemas}}


def _import_generated_module(path: Path, module_name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
    return module


def test_load_openapi_json_reads_local_input_without_fetch(monkeypatch, tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    spec_path.write_text(json.dumps(_minimal_openapi()), encoding="utf-8")

    def _unexpected_fetch(*args, **kwargs):
        _ = (args, kwargs)
        raise AssertionError("fetch should not be used when a local --input path is provided")

    monkeypatch.setattr(openapi_spec, "fetch_openapi_text", _unexpected_fetch)

    loaded = openapi_spec.load_openapi_json(spec_path)

    assert loaded["components"]["schemas"]["Example"]["type"] == "object"


def test_load_openapi_json_fetches_default_url(monkeypatch) -> None:
    calls: list[tuple[str, float]] = []

    def _fake_urlopen(url: str, timeout: float = 0.0):
        calls.append((url, timeout))
        return _DummyResponse(json.dumps(_minimal_openapi()))

    monkeypatch.setattr(openapi_spec, "urlopen", _fake_urlopen)

    loaded = openapi_spec.load_openapi_json()

    assert calls
    assert calls[0][0] == openapi_spec.DEFAULT_KSEF_OPENAPI_URL
    assert (
        loaded["paths"]["/invoices/query/metadata"]["post"]["responses"]["200"]["description"]
        == "ok"
    )


def test_load_openapi_json_falls_back_to_snapshot_when_remote_is_unavailable(
    monkeypatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    snapshot_path = tmp_path / "ksef-openapi.snapshot.json"
    snapshot_path.write_text(json.dumps(_minimal_openapi()), encoding="utf-8")

    def _offline(*args, **kwargs):
        _ = (args, kwargs)
        raise OSError("network blocked")

    monkeypatch.setattr(openapi_spec, "urlopen", _offline)

    loaded = openapi_spec.load_openapi_json(fallback_path=snapshot_path)

    assert loaded["components"]["schemas"]["Example"]["type"] == "object"
    assert "using fallback OpenAPI snapshot" in capsys.readouterr().err


def test_load_openapi_json_without_fallback_raises_on_remote_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    snapshot_path = tmp_path / "ksef-openapi.snapshot.json"
    snapshot_path.write_text(json.dumps(_minimal_openapi()), encoding="utf-8")

    def _offline(*args, **kwargs):
        _ = (args, kwargs)
        raise OSError("network blocked")

    monkeypatch.setattr(openapi_spec, "urlopen", _offline)

    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        openapi_spec.load_openapi_json(
            fallback_path=snapshot_path,
            allow_fallback=False,
        )

    assert "Failed to download OpenAPI spec" in str(exc.value)


def test_load_openapi_json_raises_when_remote_and_fallback_are_unavailable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def _offline(*args, **kwargs):
        _ = (args, kwargs)
        raise OSError("network blocked")

    monkeypatch.setattr(openapi_spec, "urlopen", _offline)

    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        openapi_spec.load_openapi_json(fallback_path=tmp_path / "missing.snapshot.json")

    assert "Fallback snapshot" in str(exc.value)


def test_load_openapi_json_raises_for_invalid_json(monkeypatch) -> None:
    monkeypatch.setattr(openapi_spec, "urlopen", lambda *args, **kwargs: _DummyResponse("not-json"))

    with pytest.raises(openapi_spec.OpenApiSpecError):
        openapi_spec.load_openapi_json()


def test_generate_models_writes_output_from_local_spec(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"
    spec_path.write_text(json.dumps(_minimal_openapi()), encoding="utf-8")

    generator.generate_models(spec_path, output_path)

    content = output_path.read_text(encoding="utf-8")
    assert "class Example(OpenApiModel):" in content
    assert 'reference_number: str = field(metadata={"json_key": "referenceNumber"})' in content
    assert (
        'is_active: Optional[bool] = field(default=None, metadata={"json_key": "isActive"})'
        in content
    )


def test_generate_models_updates_snapshot_after_successful_remote_fetch(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "openapi_models.py"
    snapshot_path = tmp_path / "ksef-openapi.snapshot.json"

    monkeypatch.setattr(
        openapi_spec,
        "urlopen",
        lambda *args, **kwargs: _DummyResponse(json.dumps(_minimal_openapi())),
    )

    generator.generate_models(None, output_path, snapshot_path=snapshot_path)

    assert snapshot_path.exists()
    assert json.loads(snapshot_path.read_text(encoding="utf-8"))["openapi"] == "3.0.0"


def test_check_generated_models_detects_diff(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"
    spec_path.write_text(json.dumps(_minimal_openapi()), encoding="utf-8")

    generator.generate_models(spec_path, output_path)
    assert generator.check_generated_models(spec_path, output_path) is None

    output_path.write_text("stale\n", encoding="utf-8")
    diff = generator.check_generated_models(spec_path, output_path)

    assert diff is not None
    assert "generated-openapi-models" in diff


def test_generate_models_without_fallback_raises_when_remote_is_unavailable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "openapi_models.py"

    def _offline(*args, **kwargs):
        _ = (args, kwargs)
        raise OSError("network blocked")

    monkeypatch.setattr(openapi_spec, "urlopen", _offline)

    with pytest.raises(openapi_spec.OpenApiSpecError):
        generator.generate_models(None, output_path, allow_fallback=False)


def test_generate_models_escapes_hostile_enum_value(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Wartość enuma jest danymi: ląduje w literale, nie w kodzie do wykonania."""
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"
    spec_path.write_text(
        json.dumps(_schemas_openapi({"EvilEnum": {"enum": [HOSTILE_ENUM_VALUE]}})),
        encoding="utf-8",
    )

    generator.generate_models(spec_path, output_path)

    rendered = output_path.read_text(encoding="utf-8")
    assert HOSTILE_ENUM_VALUE not in rendered
    assert "PWN-A-ENUM" in rendered

    module = _import_generated_module(output_path, "_hostile_enum_models")

    assert "PWN-A-ENUM" not in capsys.readouterr().out
    assert next(iter(module.EvilEnum)).value == HOSTILE_ENUM_VALUE


def test_generate_models_rejects_hostile_schema_name(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"
    spec_path.write_text(
        json.dumps(_schemas_openapi({HOSTILE_SCHEMA_NAME: {"enum": ["ok"]}})),
        encoding="utf-8",
    )

    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        generator.generate_models(spec_path, output_path)

    message = str(exc.value)
    assert "Schema name" in message
    assert "is not a valid Python identifier" in message
    assert "PWN-B-CLASS" in message
    assert HOSTILE_SCHEMA_NAME not in message
    assert not output_path.exists()


def test_generate_models_rejects_hostile_property_name(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"
    spec_path.write_text(
        json.dumps(
            _schemas_openapi(
                {
                    "EvilObject": {
                        "type": "object",
                        "properties": {HOSTILE_PROPERTY_NAME: {"type": "string"}},
                    }
                }
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        generator.generate_models(spec_path, output_path)

    message = str(exc.value)
    assert "Property name" in message
    assert "schema EvilObject" in message
    assert "PWN-C-PROPNAME" in message
    assert HOSTILE_PROPERTY_NAME not in message
    assert not output_path.exists()


def test_generate_models_rejects_field_name_broken_by_sanitization(tmp_path: Path) -> None:
    """`_0` jest poprawnym identyfikatorem, ale sanitacja ścina z niego `0`."""
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"
    spec_path.write_text(
        json.dumps(
            _schemas_openapi(
                {
                    "EvilObject": {
                        "type": "object",
                        "properties": {"_0": {"type": "string"}},
                    }
                }
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        generator.generate_models(spec_path, output_path)

    message = str(exc.value)
    assert "Field name '0'" in message
    assert "property '_0'" in message
    assert not output_path.exists()


def test_generate_models_rejects_keyword_schema_name(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    spec_path.write_text(
        json.dumps(_schemas_openapi({"class": {"enum": ["ok"]}})),
        encoding="utf-8",
    )

    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        generator.generate_models(spec_path, tmp_path / "openapi_models.py")

    assert "reserved Python keyword" in str(exc.value)


def test_generate_models_rejects_invalid_ref_names(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"

    def _spec_with_ref(ref: object) -> dict[str, object]:
        return _schemas_openapi(
            {
                "Example": {
                    "type": "object",
                    "properties": {"value": {"$ref": ref}},
                }
            }
        )

    spec_path.write_text(
        json.dumps(_spec_with_ref("#/components/schemas/Evil\nimport sys")),
        encoding="utf-8",
    )
    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        generator.generate_models(spec_path, output_path)
    assert "Referenced schema name" in str(exc.value)
    assert not output_path.exists()

    spec_path.write_text(json.dumps(_spec_with_ref(123)), encoding="utf-8")
    with pytest.raises(openapi_spec.OpenApiSpecError) as exc:
        generator.generate_models(spec_path, output_path)
    assert "expected a string" in str(exc.value)
    assert not output_path.exists()


def test_generate_models_marks_sensitive_fields_as_not_repr(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.json"
    output_path = tmp_path / "openapi_models.py"
    spec_path.write_text(
        json.dumps(
            _schemas_openapi(
                {
                    "Credentials": {
                        "type": "object",
                        "required": ["token"],
                        "properties": {
                            "token": {"type": "string"},
                            "accessToken": {"type": "string"},
                            "name": {"type": "string"},
                        },
                    }
                }
            )
        ),
        encoding="utf-8",
    )

    generator.generate_models(spec_path, output_path)

    rendered = output_path.read_text(encoding="utf-8")
    assert "token: str = field(repr=False)" in rendered
    assert (
        'access_token: Optional[str] = field(default=None, repr=False, '
        'metadata={"json_key": "accessToken"})' in rendered
    )
    # Pola bez sekretów zachowują dotychczasową, krótszą postać.
    assert "name: Optional[str] = None" in rendered


def test_coverage_tool_detects_typed_request_helpers(tmp_path: Path) -> None:
    client_file = tmp_path / "client.py"
    client_file.write_text(
        "\n".join(
            [
                "class Client:",
                "    def endpoints(self, reference_number):",
                '        self._request_model("GET", "/auth/sessions")',
                '        self._request_optional_model("POST", f"/auth/{reference_number}")',
                '        self._request_model_list("GET", "/security/public-key-certificates")',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    endpoints = coverage_tool.get_implemented_endpoints_deep(tmp_path)
    keys = {(endpoint.method, endpoint.normalized_path) for endpoint in endpoints}

    assert ("GET", "/auth/sessions") in keys
    assert ("POST", "/auth/{}") in keys
    assert ("GET", "/security/public-key-certificates") in keys


def test_check_coverage_uses_allow_fallback_flag(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def _fake_load_openapi_json(path, *, allow_fallback=True, **kwargs):
        captured["path"] = path
        captured["allow_fallback"] = allow_fallback
        captured["kwargs"] = kwargs
        return _minimal_openapi()

    monkeypatch.setattr(coverage_tool, "load_openapi_json", _fake_load_openapi_json)
    monkeypatch.setattr(coverage_tool, "get_implemented_endpoints_deep", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        coverage_tool.sys,
        "argv",
        ["check_coverage.py", "--src", str(tmp_path), "--no-fallback"],
    )

    with pytest.raises(SystemExit) as exc:
        coverage_tool.main()

    assert exc.value.code == 1
    assert captured["allow_fallback"] is False
