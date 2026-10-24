from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ksef_client import models as m
from ksef_client import redact_sensitive
from ksef_client.services.workflows import AuthResult


def test_nested_secrets_and_wire_serialization():
    marker = "DUMMY_SECRET"
    part = m.PartUploadRequest(
        headers={"Authorization": marker},
        method="PUT",
        ordinal_number=1,
        url=f"https://example.invalid/?sig={marker}",
    )
    result = AuthResult("ref", marker, m.AuthenticationTokensResponse.from_dict({}))
    assert marker not in repr([part, result])
    assert marker not in str(redact_sensitive([part, result]))
    assert marker in part.to_dict()["url"]
    assert marker not in repr(m.BinaryContent(marker.encode()))
    assert marker not in repr(m.InvoiceContent(marker))


def test_diagnostics_are_bounded_and_never_call_unknown_repr():
    class Hostile:
        def __repr__(self):
            raise AssertionError("repr must not run")

    class Kind(Enum):
        ONE = "one"

    @dataclass
    class Hidden:
        secret_value: str = field(repr=False)

    cycle: dict[str, Any] = {}
    cycle["self"] = cycle
    values = {
        "Authorization": "SECRET",
        "accessToken": "SECRET",
        "next_cursor": "SECRET",
        "obj": Hostile(),
        "bytes": b"SECRET",
        "nested": (Hidden("SECRET"), Kind.ONE),
        "set": {1},
        "frozen": frozenset({2}),
        "class": Hidden,
        1: Hostile(),
        "values": [None, True, 1, 1.5, "public"],
        "cycle": cycle,
    }
    result = redact_sensitive(values)
    assert "SECRET" not in str(result)
    assert result["obj"] == "<Hostile>"
    assert result["nested"] == [{"secret_value": "<redacted>"}, "one"]
    assert "<cycle>" in str(result)


def test_generated_field_policy_is_also_redacted_in_dictionary_diagnostics():
    from tools.generate_openapi_models import SENSITIVE_FIELD_NAMES
    payload = dict.fromkeys(SENSITIVE_FIELD_NAMES, "DUMMY_SECRET")
    assert "DUMMY_SECRET" not in str(redact_sensitive(payload))
