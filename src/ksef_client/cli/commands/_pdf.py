"""Shared local PDF command execution."""

from pathlib import Path
from typing import Literal, cast

import typer

from ksef_client._private_files import write_private_file
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.exceptions import KsefDocumentValidationError, KsefRenderingError
from ksef_client.facade import connection_options
from ksef_client.invoice_pdf import InvoicePdfContext, render_invoice_pdf, render_upo_pdf
from ksef_client.services.xades import XadesKeyPair

from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ._workflow import workflow_errors


def render_file(
    ctx: typer.Context,
    file: Path,
    out: Path,
    *,
    upo: bool = False,
    renderer: str = "mf",
    number: str | None = None,
    env: str | None = None,
    offline: bool = False,
    cert: Path | None = None,
    key: Path | None = None,
    pkcs12: Path | None = None,
    password: str | None = None,
) -> None:
    command = "upo.render" if upo else "invoice.render"
    with workflow_errors(ctx, command):
        with file.open("rb") as stream:
            xml = stream.read((32 if upo else 20) * 1024 * 1024 + 1)
        context = None
        if number or offline:
            if renderer != "mf" or (number and offline):
                raise ValueError("Use MF with either a KSeF number or offline verification")
            if offline or not env:
                options, kind, value = connection_options(
                    profile=require_profile(require_context(ctx))
                )
            else:
                options, kind, value = KsefClientOptions(base_url=""), "", ""
            if env:
                try:
                    options = KsefClientOptions(base_url=KsefEnvironment[env.upper()].value)
                except KeyError:
                    raise ValueError("Environment must be TEST, DEMO or PROD") from None
            if offline:
                if pkcs12 and (cert or key):
                    raise ValueError("Choose PKCS#12 or a PEM certificate and key")
                if pkcs12:
                    signer = XadesKeyPair.from_pkcs12_file(
                        pkcs12_path=str(pkcs12), pkcs12_password=password
                    )
                elif cert and key:
                    signer = XadesKeyPair.from_pem_files(
                        certificate_path=str(cert),
                        private_key_path=str(key),
                        private_key_password=password,
                    )
                else:
                    raise ValueError("Offline rendering requires a PEM pair or PKCS#12")
                context = InvoicePdfContext.offline(options, kind, value, signer)
            else:
                context = InvoicePdfContext.accepted(options, number or "")
        elif cert or key or pkcs12 or password:
            raise ValueError("Certificate options require --offline")
        try:
            pdf = (
                render_upo_pdf(xml)
                if upo
                else render_invoice_pdf(
                    xml,
                    ksef_number=number,
                    renderer=cast(Literal["local", "mf"], renderer),
                    context=context,
                )
            )
        except KsefRenderingError as exc:
            raise CliError(
                str(exc), ExitCode.CONFIG_ERROR, "Install Node.js 22 or newer and retry."
            ) from None
        except ImportError:
            raise CliError(
                "Local PDF rendering requires ksef-client[pdf]", ExitCode.CONFIG_ERROR
            ) from None
        except KsefDocumentValidationError as exc:
            raise CliError(str(exc), ExitCode.VALIDATION_ERROR) from None
        write_private_file(out, pdf)
        get_renderer(require_context(ctx)).success(
            command=command,
            profile=profile_label(require_context(ctx)),
            data={"saved": str(out), "bytes": len(pdf)},
        )
