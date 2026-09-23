import json

from tools.openapi_spec import extract_api_version


def test_extract_api_version_from_real_snapshot() -> None:
    from pathlib import Path

    text = Path("specs/ksef-openapi.snapshot.json").read_text(encoding="utf-8")

    assert extract_api_version(text) == "2.8.1"


def test_extract_api_version_returns_none_instead_of_raising() -> None:
    """Zmiana formatu opisu MF nie może wywalić workflow driftu (`IndexError`)."""
    # Każdy wariant musi dać konkretny wynik: `None` (nie da się odczytać) albo
    # poprawną wersję. Samo `isinstance` niczego by tu nie sprawdzało.
    variants: list[tuple[str, str | None]] = [
        ("", None),
        ("to nie jest json", None),
        ("[]", None),
        (json.dumps({}), None),
        (json.dumps({"info": {}}), None),
        (json.dumps({"info": {"description": ""}}), None),
        (json.dumps({"info": {"description": "Wersja API: 2.8.1"}}), None),
        (json.dumps({"info": {"description": 123}}), None),
        (json.dumps({"info": "nie-obiekt"}), None),
        (
            json.dumps({"info": {"description": "**Wersja API:** 2.8.1 (build x)"}}),
            "2.8.1",
        ),
    ]

    for text, expected in variants:
        assert extract_api_version(text) == expected, text


def test_extract_api_version_parses_common_shapes() -> None:
    def _spec(description: str) -> str:
        return json.dumps({"info": {"description": description}})

    assert extract_api_version(_spec("**Wersja API:** 2.8.1 (build abc)")) == "2.8.1"
    assert extract_api_version(_spec("**Wersja API:** 2.8.1")) == "2.8.1"
    assert extract_api_version(_spec("prefix **Wersja API:** 3.0.0-rc1 (build z)")) == "3.0.0-rc1"
    assert extract_api_version(_spec("**Wersja API:**2.8.1 (build z)")) == "2.8.1"
