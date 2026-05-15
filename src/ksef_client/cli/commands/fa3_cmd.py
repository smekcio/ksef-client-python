from __future__ import annotations

from pathlib import Path

import typer

from ksef_client.documents.fa3 import (
    FA3BatchDraft,
    FA3Importer,
    FA3Template,
    ImportMode,
    audit_fa3_xsd_coverage,
    validate_fa3_xml_xsd,
)

from ..context import profile_label, require_context
from ..exit_codes import ExitCode
from ..output import get_renderer

app = typer.Typer(help="Build, validate, and inspect FA(3) documents.")


@app.command("template")
def template(
    ctx: typer.Context,
    out: str = typer.Option(..., "--out", help="Path for the generated XLSX template."),
    sample: bool = typer.Option(True, "--sample/--no-sample", help="Include a sample row."),
) -> None:
    renderer = get_renderer(require_context(ctx))
    profile = profile_label(require_context(ctx))
    try:
        FA3Template.create_xlsx(out, sample=sample)
    except Exception as exc:
        _render_error(renderer, profile, "fa3.template", exc)
    renderer.success(
        command="fa3.template",
        profile=profile,
        data={"path": str(Path(out).resolve())},
    )


@app.command("import")
def import_file(
    ctx: typer.Context,
    source: str = typer.Option(..., "--source", help="Input XLSX or JSON draft file."),
    report: str | None = typer.Option(None, "--report", help="Optional XLSX error report path."),
) -> None:
    renderer = get_renderer(require_context(ctx))
    profile = profile_label(require_context(ctx))
    try:
        result = _import_source(source, mode=ImportMode.PARTIAL_WITH_REPORT)
        if report:
            result.to_error_report_xlsx(report)
    except Exception as exc:
        _render_error(renderer, profile, "fa3.import", exc)
    renderer.success(
        command="fa3.import",
        profile=profile,
        data={
            "valid": len(result.valid_drafts),
            "invalid": len(result.invalid_rows),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "report": str(Path(report).resolve()) if report else None,
        },
    )


@app.command("build")
def build(
    ctx: typer.Context,
    source: str = typer.Option(..., "--source", help="Input XLSX or JSON draft file."),
    out: str = typer.Option(..., "--out", help="Output XML directory or ZIP file."),
    zip_output: bool = typer.Option(
        False,
        "--zip/--files",
        help="Write a ZIP instead of XML files.",
    ),
    xsd_validate: bool = typer.Option(False, "--xsd/--no-xsd", help="Validate generated XML."),
) -> None:
    renderer = get_renderer(require_context(ctx))
    profile = profile_label(require_context(ctx))
    try:
        result = _import_source(source, mode=ImportMode.PARTIAL_WITH_REPORT)
        if result.errors:
            raise ValueError(f"Input contains {len(result.errors)} FA(3) validation errors.")
        batch = FA3BatchDraft(tuple(result.valid_drafts))
        if xsd_validate:
            for draft in batch.drafts:
                draft.to_xml(xsd_validate=True)
        written = [batch.to_xml_zip(out)] if zip_output else batch.to_xml_files(out)
    except Exception as exc:
        _render_error(renderer, profile, "fa3.build", exc)
    renderer.success(
        command="fa3.build",
        profile=profile,
        data={
            "count": len(written),
            "paths": [str(path.resolve()) for path in written],
        },
    )


@app.command("validate")
def validate(
    ctx: typer.Context,
    invoice: str = typer.Option(..., "--invoice", help="FA(3) XML file to validate."),
) -> None:
    renderer = get_renderer(require_context(ctx))
    profile = profile_label(require_context(ctx))
    try:
        validate_fa3_xml_xsd(Path(invoice).read_bytes())
    except Exception as exc:
        _render_error(renderer, profile, "fa3.validate", exc)
    renderer.success(
        command="fa3.validate",
        profile=profile,
        data={"path": str(Path(invoice).resolve()), "xsd": "valid"},
    )


@app.command("inspect")
def inspect(
    ctx: typer.Context,
    source: str = typer.Option(..., "--source", help="Input XLSX or JSON draft file."),
) -> None:
    renderer = get_renderer(require_context(ctx))
    profile = profile_label(require_context(ctx))
    try:
        result = _import_source(source, mode=ImportMode.VALIDATE_ONLY)
        coverage = audit_fa3_xsd_coverage()
    except Exception as exc:
        _render_error(renderer, profile, "fa3.inspect", exc)
    renderer.success(
        command="fa3.inspect",
        profile=profile,
        data={
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "xsd_elements": len(coverage.elements),
            "coverage_entries": len(coverage.coverage),
        },
    )


def _import_source(source: str, *, mode: ImportMode):
    path = Path(source)
    suffix = path.suffix.lower()
    if suffix == ".xlsx":
        return FA3Importer.from_xlsx(path, mode=mode)
    if suffix == ".json":
        return FA3Importer.from_json(path, mode=mode)
    raise ValueError("Unsupported FA(3) source. Use .xlsx or .json.")


def _render_error(renderer, profile: str, command: str, exc: Exception) -> None:
    renderer.error(
        command=command,
        profile=profile,
        code="VALIDATION_ERROR",
        message=str(exc),
        hint="Fix the FA(3) input and retry.",
    )
    raise typer.Exit(int(ExitCode.VALIDATION_ERROR))
