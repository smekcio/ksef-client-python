from __future__ import annotations

from pathlib import Path

import pytest

import ksef_client.cli.session_store as session_store
from ksef_client import models as m
from ksef_client.cli.errors import CliError
from ksef_client.cli.session_store import (
    BatchPayloadSource,
    BatchSessionCheckpoint,
    OnlineSessionCheckpoint,
    delete_checkpoint,
    export_checkpoint,
    import_checkpoint,
    list_checkpoints,
    load_checkpoint,
    save_checkpoint,
    update_checkpoint,
)
from ksef_client.services.sessions import BatchSessionState, OnlineSessionState


def _form_code() -> m.FormCode:
    return m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")


def _online_checkpoint() -> OnlineSessionCheckpoint:
    return OnlineSessionCheckpoint(
        id="online-demo",
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        stage="opened",
        session_state=OnlineSessionState(
            reference_number="SES-ONLINE-1",
            form_code=_form_code(),
            valid_until="2026-04-01T12:30:00Z",
            symmetric_key_base64="AQID",
            iv_base64="BAUG",
        ),
    )


def _batch_checkpoint() -> BatchSessionCheckpoint:
    return BatchSessionCheckpoint(
        id="batch-demo",
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        stage="opened",
        session_state=BatchSessionState(
            reference_number="SES-BATCH-1",
            form_code=_form_code(),
            batch_file=m.BatchFileInfo.from_dict(
                {
                    "fileSize": 10,
                    "fileHash": "hash",
                    "fileParts": [{"ordinalNumber": 1, "fileSize": 10, "fileHash": "hash-part"}],
                }
            ),
            part_upload_requests=[
                m.PartUploadRequest.from_dict(
                    {
                        "ordinalNumber": 1,
                        "url": "https://upload/1",
                        "method": "PUT",
                        "headers": {},
                    }
                )
            ],
            symmetric_key_base64="AQID",
            iv_base64="BAUG",
        ),
        payload_source=BatchPayloadSource(
            kind="zip",
            path="C:/tmp/invoices.zip",
            source_sha256_base64="hash",
            source_size=10,
        ),
    )


def test_session_store_roundtrip_and_list(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    checkpoint = _online_checkpoint()

    saved_path = save_checkpoint(checkpoint)
    assert saved_path.exists()

    loaded = load_checkpoint("demo", checkpoint.id)
    assert loaded.to_dict() == checkpoint.to_dict()
    assert isinstance(loaded, OnlineSessionCheckpoint)

    updated = update_checkpoint(loaded, stage="closed", last_invoice_ref="INV-1")
    assert isinstance(updated, OnlineSessionCheckpoint)
    assert updated.stage == "closed"
    assert updated.last_invoice_ref == "INV-1"

    listed = list_checkpoints("demo")
    assert [item.id for item in listed] == [checkpoint.id]


def test_session_store_export_import_delete_and_overwrite(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    checkpoint = _batch_checkpoint()
    save_checkpoint(checkpoint)

    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    exported = export_checkpoint("demo", checkpoint.id, export_dir)
    assert exported.exists()

    delete_checkpoint("demo", checkpoint.id)
    assert list_checkpoints("demo") == []

    imported = import_checkpoint("demo", exported)
    assert imported.id == checkpoint.id

    replaced = import_checkpoint("demo", exported, session_id="batch-other")
    assert replaced.id == "batch-other"
    assert load_checkpoint("demo", "batch-other").id == "batch-other"


def test_session_store_rejects_invalid_payload_and_profile_mismatch(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    checkpoint = _online_checkpoint()
    save_checkpoint(checkpoint)

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{bad", encoding="utf-8")
    with pytest.raises(CliError):
        import_checkpoint("demo", bad_path)

    mismatch_path = tmp_path / "mismatch.json"
    payload = checkpoint.to_dict()
    payload["profile"] = "other"
    mismatch_path.write_text(__import__("json").dumps(payload), encoding="utf-8")
    with pytest.raises(CliError):
        import_checkpoint("demo", mismatch_path)


def test_session_store_rejects_duplicate_id_without_overwrite(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    checkpoint = _online_checkpoint()
    save_checkpoint(checkpoint)

    with pytest.raises(CliError):
        save_checkpoint(checkpoint, overwrite=False)


def test_session_store_skips_corrupted_items_in_list(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    checkpoint = _online_checkpoint()
    save_checkpoint(checkpoint)

    broken_path = tmp_path / "local" / "ksef-cli" / "sessions" / "demo" / "broken.json"
    broken_path.parent.mkdir(parents=True, exist_ok=True)
    broken_path.write_text("{", encoding="utf-8")

    listed = list_checkpoints("demo")
    assert [item.id for item in listed] == [checkpoint.id]


@pytest.mark.parametrize(
    ("helper_name", "value"),
    [
        ("_optional_string", 1),
        ("_required_string", " "),
        ("_required_int", -1),
        ("_required_string_list", {"bad": True}),
        ("_required_string_list", ["ok", 2]),
        ("_required_int_list", {"bad": True}),
        ("_required_int_list", [1, -1]),
    ],
)
def test_session_store_private_validators_reject_invalid_values(
    helper_name: str, value: object
) -> None:
    helper = getattr(session_store, helper_name)
    with pytest.raises(ValueError):
        helper(value, field_name="field")


def test_session_store_rejects_invalid_ids_and_checkpoint_shapes() -> None:
    with pytest.raises(CliError):
        session_store._validate_session_id(" bad id ")

    with pytest.raises(ValueError):
        BatchPayloadSource(kind="bad", path="x", source_sha256_base64="hash", source_size=1)
    with pytest.raises(ValueError):
        BatchPayloadSource(kind="zip", path=" ", source_sha256_base64="hash", source_size=1)
    with pytest.raises(ValueError):
        BatchPayloadSource(kind="zip", path="x", source_sha256_base64="hash", source_size=-1)
    with pytest.raises(ValueError):
        BatchPayloadSource(kind="zip", path="x", source_sha256_base64=" ", source_size=1)

    with pytest.raises(ValueError):
        OnlineSessionCheckpoint(
            id="online-demo",
            profile="demo",
            base_url="https://example.invalid",
            stage="opened",
            session_state=_online_checkpoint().session_state,
            schema_version=2,
        )
    with pytest.raises(ValueError):
        OnlineSessionCheckpoint(
            id="online-demo",
            profile="demo",
            base_url="https://example.invalid",
            stage="opened",
            session_state=_online_checkpoint().session_state,
            kind="batch",
        )
    with pytest.raises(ValueError):
        OnlineSessionCheckpoint(
            id="online-demo",
            profile=" ",
            base_url="https://example.invalid",
            stage="opened",
            session_state=_online_checkpoint().session_state,
        )
    with pytest.raises(ValueError):
        OnlineSessionCheckpoint(
            id="online-demo",
            profile="demo",
            base_url=" ",
            stage="opened",
            session_state=_online_checkpoint().session_state,
        )
    with pytest.raises(ValueError):
        OnlineSessionCheckpoint(
            id="online-demo",
            profile="demo",
            base_url="https://example.invalid",
            stage=" ",
            session_state=_online_checkpoint().session_state,
        )

    with pytest.raises(ValueError):
        BatchSessionCheckpoint(
            id="batch-demo",
            profile="demo",
            base_url="https://example.invalid",
            stage="opened",
            session_state=_batch_checkpoint().session_state,
            payload_source=_batch_checkpoint().payload_source,
            schema_version=2,
        )
    with pytest.raises(ValueError):
        BatchSessionCheckpoint(
            id="batch-demo",
            profile="demo",
            base_url="https://example.invalid",
            stage="opened",
            session_state=_batch_checkpoint().session_state,
            payload_source=_batch_checkpoint().payload_source,
            kind="online",
        )
    with pytest.raises(ValueError):
        BatchSessionCheckpoint(
            id="batch-demo",
            profile=" ",
            base_url="https://example.invalid",
            stage="opened",
            session_state=_batch_checkpoint().session_state,
            payload_source=_batch_checkpoint().payload_source,
        )
    with pytest.raises(ValueError):
        BatchSessionCheckpoint(
            id="batch-demo",
            profile="demo",
            base_url=" ",
            stage="opened",
            session_state=_batch_checkpoint().session_state,
            payload_source=_batch_checkpoint().payload_source,
        )
    with pytest.raises(ValueError):
        BatchSessionCheckpoint(
            id="batch-demo",
            profile="demo",
            base_url="https://example.invalid",
            stage=" ",
            session_state=_batch_checkpoint().session_state,
            payload_source=_batch_checkpoint().payload_source,
        )


def test_session_store_checkpoint_from_dict_rejects_invalid_shapes() -> None:
    online_payload = _online_checkpoint().to_dict()
    with pytest.raises(ValueError):
        OnlineSessionCheckpoint.from_dict(online_payload | {"schema_version": 2})
    with pytest.raises(ValueError):
        OnlineSessionCheckpoint.from_dict(online_payload | {"kind": "batch"})
    with pytest.raises(ValueError):
        OnlineSessionCheckpoint.from_dict(online_payload | {"session_state": []})

    batch_payload = _batch_checkpoint().to_dict()
    with pytest.raises(ValueError):
        BatchSessionCheckpoint.from_dict(batch_payload | {"schema_version": 2})
    with pytest.raises(ValueError):
        BatchSessionCheckpoint.from_dict(batch_payload | {"kind": "online"})
    with pytest.raises(ValueError):
        BatchSessionCheckpoint.from_dict(batch_payload | {"session_state": []})
    with pytest.raises(ValueError):
        BatchSessionCheckpoint.from_dict(batch_payload | {"payload_source": []})

    with pytest.raises(CliError):
        session_store.checkpoint_from_dict({"kind": "online"})
    with pytest.raises(CliError):
        session_store.checkpoint_from_dict({"kind": "mystery"})


def test_session_store_handles_atomic_write_errors_and_posix_permissions(
    monkeypatch, tmp_path: Path
) -> None:
    target = tmp_path / "checkpoint.json"
    chmod_calls: list[tuple[Path, int]] = []

    monkeypatch.setattr(session_store.os, "name", "posix", raising=False)
    monkeypatch.setattr(
        session_store.os,
        "chmod",
        lambda path, mode: chmod_calls.append((Path(path), mode)),
    )
    session_store._write_json_atomic(target, {"id": "ok"})
    assert target.exists()
    assert [(Path(path).as_posix(), mode) for path, mode in chmod_calls] == [
        (target.as_posix(), 0o600)
    ]

    def _boom_replace(src: str, dst: str) -> None:
        raise OSError("nope")

    monkeypatch.setattr(session_store.os, "replace", _boom_replace)
    with pytest.raises(CliError):
        session_store._write_json_atomic(tmp_path / "broken.json", {"id": "bad"})


def test_session_store_handles_read_and_delete_failures(monkeypatch, tmp_path: Path) -> None:
    non_object = tmp_path / "non-object.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(CliError):
        session_store._read_json(non_object)

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert list_checkpoints("missing") == []

    with pytest.raises(CliError):
        load_checkpoint("demo", "missing")

    checkpoint = _online_checkpoint()
    save_checkpoint(checkpoint)
    with pytest.raises(CliError):
        delete_checkpoint("demo", "missing")

    def _boom_unlink(self) -> None:
        _ = self
        raise OSError("locked")

    monkeypatch.setattr(Path, "unlink", _boom_unlink)
    with pytest.raises(CliError):
        delete_checkpoint("demo", checkpoint.id)


def test_session_store_export_trailing_slash_and_import_missing_file(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    checkpoint = _online_checkpoint()
    save_checkpoint(checkpoint)

    export_root = tmp_path / "exports"

    class _TrailingSlashPath:
        def exists(self) -> bool:
            return False

        def is_dir(self) -> bool:
            return False

        def __str__(self) -> str:
            return f"{export_root.as_posix()}/"

    exported = export_checkpoint("demo", checkpoint.id, _TrailingSlashPath())  # type: ignore[arg-type]
    assert exported.name == f"session-{checkpoint.id}.json"

    with pytest.raises(CliError):
        import_checkpoint("demo", tmp_path / "missing.json")
