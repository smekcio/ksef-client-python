from __future__ import annotations

import json
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
