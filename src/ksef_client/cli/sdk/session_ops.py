from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from ksef_client.services import BatchSessionHandle, BatchUploadHelper
from ksef_client.services.crypto import get_file_metadata
from ksef_client.services.workflows import BatchSessionWorkflow, OnlineSessionWorkflow

from ..errors import CliError
from ..exit_codes import ExitCode
from ..session_store import (
    BatchPayloadSource,
    BatchSessionCheckpoint,
    OnlineSessionCheckpoint,
    SessionCheckpoint,
    delete_checkpoint,
    export_checkpoint,
    import_checkpoint,
    list_checkpoints,
    load_checkpoint,
    save_checkpoint,
    update_checkpoint,
)
from . import adapters


def _normalize_source_path(path: str) -> str:
    return str(Path(path).resolve())


def _build_batch_payload_source(
    *,
    zip_path: str | None,
    directory: str | None,
) -> tuple[bytes, BatchPayloadSource]:
    selected = [bool(zip_path), bool(directory)]
    if sum(1 for flag in selected if flag) != 1:
        raise CliError(
            "Select exactly one batch input source.",
            ExitCode.VALIDATION_ERROR,
            "Use one of: --zip or --dir.",
        )

    if zip_path:
        normalized_path = _normalize_source_path(zip_path)
        zip_bytes = adapters._load_batch_zip(normalized_path)
        metadata = get_file_metadata(zip_bytes)
        return zip_bytes, BatchPayloadSource(
            kind="zip",
            path=normalized_path,
            source_sha256_base64=metadata.sha256_base64,
            source_size=metadata.file_size,
        )

    normalized_path = _normalize_source_path(directory or "")
    zip_bytes = adapters._build_zip_from_directory(normalized_path)
    metadata = get_file_metadata(zip_bytes)
    return zip_bytes, BatchPayloadSource(
        kind="directory",
        path=normalized_path,
        source_sha256_base64=metadata.sha256_base64,
        source_size=metadata.file_size,
    )


def _load_batch_source_bytes(source: BatchPayloadSource) -> bytes:
    if source.kind == "zip":
        zip_bytes = adapters._load_batch_zip(source.path)
    else:
        zip_bytes = adapters._build_zip_from_directory(source.path)

    metadata = get_file_metadata(zip_bytes)
    if (
        metadata.file_size != source.source_size
        or metadata.sha256_base64 != source.source_sha256_base64
    ):
        raise CliError(
            "Batch payload source changed since session checkpoint was created.",
            ExitCode.VALIDATION_ERROR,
            "Restore the original ZIP/directory contents or open a new batch session.",
        )
    return zip_bytes


def _require_online_checkpoint(profile: str, session_id: str) -> OnlineSessionCheckpoint:
    checkpoint = load_checkpoint(profile, session_id)
    if not isinstance(checkpoint, OnlineSessionCheckpoint):
        raise CliError(
            f"Session checkpoint '{session_id}' is not an online session.",
            ExitCode.VALIDATION_ERROR,
            "Use the batch subcommands for this checkpoint.",
        )
    return checkpoint


def _require_batch_checkpoint(profile: str, session_id: str) -> BatchSessionCheckpoint:
    checkpoint = load_checkpoint(profile, session_id)
    if not isinstance(checkpoint, BatchSessionCheckpoint):
        raise CliError(
            f"Session checkpoint '{session_id}' is not a batch session.",
            ExitCode.VALIDATION_ERROR,
            "Use the online subcommands for this checkpoint.",
        )
    return checkpoint


def _ensure_checkpoint_not_closed(
    checkpoint: SessionCheckpoint,
    *,
    command_name: str,
    next_step: str,
) -> None:
    if checkpoint.stage != "closed":
        return
    raise CliError(
        f"Session checkpoint '{checkpoint.id}' is already closed.",
        ExitCode.VALIDATION_ERROR,
        f"Open a new session checkpoint before running `{command_name}`. {next_step}",
    )


def _checkpoint_summary(checkpoint: SessionCheckpoint) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": checkpoint.id,
        "kind": checkpoint.kind,
        "profile": checkpoint.profile,
        "base_url": checkpoint.base_url,
        "stage": checkpoint.stage,
        "created_at": checkpoint.created_at,
        "updated_at": checkpoint.updated_at,
        "session_ref": checkpoint.session_state.reference_number,
    }
    if isinstance(checkpoint, OnlineSessionCheckpoint):
        payload["last_invoice_ref"] = checkpoint.last_invoice_ref or ""
        payload["sent_invoice_count"] = len(checkpoint.sent_invoice_refs)
    else:
        payload["uploaded_ordinals"] = list(checkpoint.uploaded_ordinals)
        payload["last_upo_ref"] = checkpoint.last_upo_ref or ""
        payload["payload_source"] = checkpoint.payload_source.to_dict()
    return payload


def list_saved_sessions(*, profile: str) -> dict[str, Any]:
    checkpoints = list_checkpoints(profile)
    return {
        "count": len(checkpoints),
        "items": [_checkpoint_summary(checkpoint) for checkpoint in checkpoints],
    }


def show_saved_session(*, profile: str, session_id: str) -> dict[str, Any]:
    checkpoint = load_checkpoint(profile, session_id)
    return _checkpoint_summary(checkpoint) | {"checkpoint": checkpoint.to_dict()}


def export_saved_session(*, profile: str, session_id: str, out: str) -> dict[str, Any]:
    target = export_checkpoint(profile, session_id, Path(out))
    return {
        "id": session_id,
        "profile": profile,
        "path": str(target),
    }


def import_saved_session(
    *,
    profile: str,
    source_path: str,
    session_id: str | None = None,
) -> dict[str, Any]:
    checkpoint = import_checkpoint(profile, Path(source_path), session_id=session_id)
    return _checkpoint_summary(checkpoint)


def drop_saved_session(*, profile: str, session_id: str) -> dict[str, Any]:
    delete_checkpoint(profile, session_id)
    return {"id": session_id, "profile": profile, "deleted": True}


def open_online_session(
    *,
    profile: str,
    base_url: str,
    session_id: str,
    system_code: str,
    schema_version: str,
    form_value: str,
    upo_v43: bool,
) -> dict[str, Any]:
    access_token = adapters._require_access_token(profile)
    form_code = adapters._build_form_code(system_code, schema_version, form_value)

    with adapters.create_client(base_url, access_token=access_token) as client:
        certs = client.security.get_public_key_certificates()
        symmetric_cert = adapters._select_certificate(certs, "SymmetricKeyEncryption")
        workflow = OnlineSessionWorkflow(client.sessions)
        session = workflow.open_session(
            form_code=form_code,
            public_certificate=symmetric_cert,
            access_token=access_token,
            upo_v43=upo_v43,
        )
        checkpoint = OnlineSessionCheckpoint(
            id=session_id,
            profile=profile,
            base_url=base_url,
            stage="opened",
            session_state=session.get_state(),
        )
        try:
            save_checkpoint(checkpoint, overwrite=False)
        except Exception:
            with suppress(Exception):
                session.close(access_token=access_token)
            raise

    return _checkpoint_summary(checkpoint)


def send_online_session_invoice(
    *,
    profile: str,
    session_id: str,
    invoice: str,
    wait_status: bool,
    wait_upo: bool,
    poll_interval: float,
    max_attempts: int,
    save_upo: str | None,
    save_upo_overwrite: bool = False,
) -> dict[str, Any]:
    checkpoint = _require_online_checkpoint(profile, session_id)
    _ensure_checkpoint_not_closed(
        checkpoint,
        command_name="ksef session online send",
        next_step="Use `ksef session online open --id <NEW_ID>` first.",
    )
    access_token = adapters._require_access_token(profile)
    if save_upo and not wait_upo:
        raise CliError(
            "Option --save-upo requires --wait-upo.",
            ExitCode.VALIDATION_ERROR,
            "Use --wait-upo when saving UPO from session send command.",
        )
    if wait_status or wait_upo:
        adapters._validate_polling_options(poll_interval, max_attempts)

    invoice_xml = adapters._load_invoice_xml(invoice)
    with adapters.create_client(checkpoint.base_url, access_token=access_token) as client:
        workflow = OnlineSessionWorkflow(client.sessions)
        session = workflow.resume_session(checkpoint.session_state, access_token=access_token)
        send_response = session.send_invoice(invoice_xml, access_token=access_token)
        invoice_ref = adapters._extract_reference_number(send_response)
        if not invoice_ref:
            raise CliError(
                "Send response does not contain invoice reference number.",
                ExitCode.API_ERROR,
                "Check KSeF response payload.",
            )

        sent_invoice_refs = list(checkpoint.sent_invoice_refs)
        if invoice_ref not in sent_invoice_refs:
            sent_invoice_refs.append(invoice_ref)
        checkpoint = cast(
            OnlineSessionCheckpoint,
            update_checkpoint(
                checkpoint,
                stage="invoice_sent",
                last_invoice_ref=invoice_ref,
                sent_invoice_refs=sent_invoice_refs,
            ),
        )

        result: dict[str, Any] = {
            "id": checkpoint.id,
            "session_ref": checkpoint.session_state.reference_number,
            "invoice_ref": invoice_ref,
            "stage": checkpoint.stage,
        }

        if wait_status or wait_upo:
            status_payload = adapters._wait_for_invoice_status(
                client=client,
                session_ref=checkpoint.session_state.reference_number,
                invoice_ref=invoice_ref,
                access_token=access_token,
                poll_interval=poll_interval,
                max_attempts=max_attempts,
            )
            code, description, _ = adapters._extract_status_fields(status_payload)
            result["status_code"] = code
            result["status_description"] = description
            result["ksef_number"] = adapters._extract_ksef_number(status_payload)

        if wait_upo:
            upo_bytes = adapters._wait_for_invoice_upo(
                client=client,
                session_ref=checkpoint.session_state.reference_number,
                invoice_ref=invoice_ref,
                access_token=access_token,
                poll_interval=poll_interval,
                max_attempts=max_attempts,
            )
            result["upo_bytes"] = len(upo_bytes)
            if save_upo:
                upo_path = adapters._save_bytes(
                    adapters._resolve_output_path(
                        save_upo,
                        default_filename=(
                            f"upo-{checkpoint.session_state.reference_number}-{invoice_ref}.xml"
                        ),
                    ),
                    upo_bytes,
                    overwrite=save_upo_overwrite,
                )
                result["upo_path"] = str(upo_path)
            else:
                result["upo_path"] = ""

    return result


def close_online_session(
    *,
    profile: str,
    session_id: str,
) -> dict[str, Any]:
    checkpoint = _require_online_checkpoint(profile, session_id)
    _ensure_checkpoint_not_closed(
        checkpoint,
        command_name="ksef session online close",
        next_step=(
            "Use `ksef session online open --id <NEW_ID>` "
            "if you need a new resumable session."
        ),
    )
    access_token = adapters._require_access_token(profile)
    with adapters.create_client(checkpoint.base_url, access_token=access_token) as client:
        workflow = OnlineSessionWorkflow(client.sessions)
        session = workflow.resume_session(checkpoint.session_state, access_token=access_token)
        session.close(access_token=access_token)
    checkpoint = cast(OnlineSessionCheckpoint, update_checkpoint(checkpoint, stage="closed"))
    return _checkpoint_summary(checkpoint)


def open_batch_session(
    *,
    profile: str,
    base_url: str,
    session_id: str,
    zip_path: str | None,
    directory: str | None,
    system_code: str,
    schema_version: str,
    form_value: str,
    upo_v43: bool,
) -> dict[str, Any]:
    access_token = adapters._require_access_token(profile)
    form_code = adapters._build_form_code(system_code, schema_version, form_value)
    zip_bytes, payload_source = _build_batch_payload_source(zip_path=zip_path, directory=directory)

    with adapters.create_client(base_url, access_token=access_token) as client:
        certs = client.security.get_public_key_certificates()
        symmetric_cert = adapters._select_certificate(certs, "SymmetricKeyEncryption")
        workflow = BatchSessionWorkflow(client.sessions, client.http_client)
        session = workflow.open_session(
            form_code=form_code,
            zip_bytes=zip_bytes,
            public_certificate=symmetric_cert,
            access_token=access_token,
            upo_v43=upo_v43,
        )
        checkpoint = BatchSessionCheckpoint(
            id=session_id,
            profile=profile,
            base_url=base_url,
            stage="opened",
            session_state=session.get_state(),
            payload_source=payload_source,
        )
        try:
            save_checkpoint(checkpoint, overwrite=False)
        except Exception:
            with suppress(Exception):
                session.close(access_token=access_token)
            raise

    return _checkpoint_summary(checkpoint)


def upload_batch_session(
    *,
    profile: str,
    session_id: str,
    parallelism: int,
) -> dict[str, Any]:
    checkpoint = _require_batch_checkpoint(profile, session_id)
    _ensure_checkpoint_not_closed(
        checkpoint,
        command_name="ksef session batch upload",
        next_step="Use `ksef session batch open --id <NEW_ID>` to start a new batch session.",
    )
    access_token = adapters._require_access_token(profile)
    if parallelism <= 0:
        raise CliError(
            "Invalid parallelism.",
            ExitCode.VALIDATION_ERROR,
            "--parallelism must be greater than zero.",
        )

    zip_bytes = _load_batch_source_bytes(checkpoint.payload_source)
    uploaded_ordinals = sorted(set(checkpoint.uploaded_ordinals))

    with adapters.create_client(checkpoint.base_url, access_token=access_token) as client:
        workflow = BatchSessionWorkflow(client.sessions, client.http_client)
        session = workflow.resume_session(
            checkpoint.session_state,
            zip_bytes=zip_bytes,
            access_token=access_token,
        )

        def _progress(ordinal_number: int) -> None:
            nonlocal checkpoint
            if ordinal_number not in uploaded_ordinals:
                uploaded_ordinals.append(ordinal_number)
                uploaded_ordinals.sort()
                checkpoint = cast(
                    BatchSessionCheckpoint,
                    update_checkpoint(
                        checkpoint,
                        stage="uploading",
                        uploaded_ordinals=list(uploaded_ordinals),
                    ),
                )

        session.upload_parts(
            parallelism=parallelism,
            skip_ordinals=uploaded_ordinals,
            progress_callback=_progress,
        )

    checkpoint = cast(
        BatchSessionCheckpoint,
        update_checkpoint(
            checkpoint,
            stage="uploaded",
            uploaded_ordinals=list(uploaded_ordinals),
        ),
    )

    return _checkpoint_summary(checkpoint) | {
        "uploaded_count": len(uploaded_ordinals),
        "total_parts": len(checkpoint.session_state.part_upload_requests),
    }


def close_batch_session(
    *,
    profile: str,
    session_id: str,
    wait_status: bool,
    wait_upo: bool,
    poll_interval: float,
    max_attempts: int,
    save_upo: str | None,
    save_upo_overwrite: bool = False,
) -> dict[str, Any]:
    checkpoint = _require_batch_checkpoint(profile, session_id)
    if save_upo and not wait_upo:
        raise CliError(
            "Option --save-upo requires --wait-upo.",
            ExitCode.VALIDATION_ERROR,
            "Use --wait-upo when saving UPO from session close command.",
        )
    if wait_status or wait_upo:
        adapters._validate_polling_options(poll_interval, max_attempts)

    if checkpoint.stage == "closed" and not (wait_status or wait_upo):
        return _checkpoint_summary(checkpoint)

    access_token = adapters._require_access_token(profile)
    with adapters.create_client(checkpoint.base_url, access_token=access_token) as client:
        if checkpoint.stage != "closed":
            session = BatchSessionHandle.from_state(
                checkpoint.session_state,
                sessions_client=client.sessions,
                uploader=BatchUploadHelper(client.http_client),
                access_token=access_token,
            )
            session.close(access_token=access_token)
            checkpoint = cast(BatchSessionCheckpoint, update_checkpoint(checkpoint, stage="closed"))

        result: dict[str, Any] = _checkpoint_summary(checkpoint)
        if wait_status or wait_upo:
            session_status = adapters._wait_for_session_status(
                client=client,
                session_ref=checkpoint.session_state.reference_number,
                access_token=access_token,
                poll_interval=poll_interval,
                max_attempts=max_attempts,
            )
            code, description, _ = adapters._extract_status_fields(session_status)
            result["status_code"] = code
            result["status_description"] = description
            upo_ref = adapters._extract_upo_reference(session_status)
            checkpoint = cast(
                BatchSessionCheckpoint,
                update_checkpoint(checkpoint, last_upo_ref=str(upo_ref or "") or None),
            )
            result["upo_ref"] = str(upo_ref or "")

            if wait_upo:
                if not upo_ref:
                    raise CliError(
                        "UPO reference number is not available in session status.",
                        ExitCode.RETRY_EXHAUSTED,
                        "Run `ksef upo wait --session-ref <SESSION_REF> --batch-auto` later.",
                    )
                upo_bytes = adapters._wait_for_batch_upo(
                    client=client,
                    session_ref=checkpoint.session_state.reference_number,
                    upo_ref=str(upo_ref),
                    access_token=access_token,
                    poll_interval=poll_interval,
                    max_attempts=max_attempts,
                )
                result["upo_bytes"] = len(upo_bytes)
                if save_upo:
                    upo_path = adapters._save_bytes(
                        adapters._resolve_output_path(
                            save_upo,
                            default_filename=(
                                f"upo-{checkpoint.session_state.reference_number}-{upo_ref}.xml"
                            ),
                        ),
                        upo_bytes,
                        overwrite=save_upo_overwrite,
                    )
                    result["upo_path"] = str(upo_path)
                else:
                    result["upo_path"] = ""

    return result


def get_saved_session_status(
    *,
    profile: str,
    session_id: str,
    invoice_ref: str | None,
) -> dict[str, Any]:
    checkpoint = load_checkpoint(profile, session_id)
    return adapters.get_send_status(
        profile=profile,
        base_url=checkpoint.base_url,
        session_ref=checkpoint.session_state.reference_number,
        invoice_ref=invoice_ref,
    ) | {"id": checkpoint.id, "kind": checkpoint.kind, "stage": checkpoint.stage}
