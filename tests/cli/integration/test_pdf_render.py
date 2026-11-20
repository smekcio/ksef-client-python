import pytest
from tests.test_offline_invoice_state import NUMBER
from tests.test_offline_verification import signer

from ksef_client.cli import app
from ksef_client.cli.commands import _pdf
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.exceptions import KsefDocumentValidationError, KsefRenderingError


@pytest.mark.parametrize("kind", ["invoice", "upo"])
def test_cli_local_render(runner, tmp_path, monkeypatch, kind):
    monkeypatch.setattr(_pdf, "render_invoice_pdf", lambda *a, **kw: b"%PDF-test")
    monkeypatch.setattr(_pdf, "render_upo_pdf", lambda *a, **kw: b"%PDF-test")
    xml = tmp_path / "invoice.xml"
    xml.write_bytes(b"test")
    out = tmp_path / "out.pdf"
    result = runner.invoke(app, [kind, "render", str(xml), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_bytes() == b"%PDF-test"


@pytest.mark.parametrize(
    "args,code",
    [
        (["--ksef-number", NUMBER, "--env", "TEST"], 0),
        (["--ksef-number", NUMBER], 0),
        (["--ksef-number", NUMBER, "--env", "bad"], 2),
        (["--ksef-number", NUMBER, "--renderer", "local"], 2),
        (["--ksef-number", NUMBER, "--offline"], 2),
        (["--offline"], 2),
        (["--cert-pem", "cert"], 2),
    ],
)
def test_cli_verification_choices(runner, tmp_path, monkeypatch, args, code):
    monkeypatch.setattr(
        _pdf,
        "connection_options",
        lambda **kw: (KsefClientOptions(base_url=KsefEnvironment.TEST.value), "Nip", "5265877635"),
    )
    monkeypatch.setattr(_pdf, "render_invoice_pdf", lambda *a, **kw: b"%PDF-test")
    xml = tmp_path / "source.xml"
    xml.write_bytes(b"test")
    result = runner.invoke(
        app, ["invoice", "render", str(xml), "--out", str(tmp_path / "out"), *args]
    )
    assert result.exit_code == code, result.output


@pytest.mark.parametrize(
    "error,code",
    [
        (KsefRenderingError("Node unavailable"), 6),
        (KsefDocumentValidationError("bad XML"), 2),
        (ImportError(), 6),
    ],
)
def test_cli_render_errors(runner, tmp_path, monkeypatch, error, code):
    def fail(*a, **kw):
        raise error

    monkeypatch.setattr(_pdf, "render_invoice_pdf", fail)
    xml = tmp_path / "source.xml"
    xml.write_bytes(b"test")
    out = tmp_path / "out"
    result = runner.invoke(app, ["invoice", "render", str(xml), "--out", str(out)])
    assert result.exit_code == code, result.output
    assert not out.exists()


@pytest.mark.parametrize("format", ["pem", "p12", "conflict"])
def test_cli_offline_certificate_formats(runner, tmp_path, monkeypatch, format):
    pair = signer()
    cert, key = tmp_path / "cert", tmp_path / "key"
    cert.write_text(pair.certificate_pem)
    key.write_text(pair.private_key_pem)
    monkeypatch.setattr(
        _pdf,
        "connection_options",
        lambda **kw: (KsefClientOptions(base_url=KsefEnvironment.TEST.value), "Nip", "5265877635"),
    )

    def render(*a, **kw):
        assert kw["context"].mode == "offline"
        return b"%PDF-test"

    monkeypatch.setattr(_pdf, "render_invoice_pdf", render)
    monkeypatch.setattr(_pdf.XadesKeyPair, "from_pkcs12_file", lambda **kw: pair)
    xml = tmp_path / "source.xml"
    xml.write_bytes(b"test")
    flags = ["--cert-pem", str(cert), "--key-pem", str(key)] if format != "p12" else []
    if format != "pem":
        flags += ["--pkcs12-path", "example.p12"]
    result = runner.invoke(
        app, ["invoice", "render", str(xml), "--out", str(tmp_path / "out"), "--offline", *flags]
    )
    assert result.exit_code == (2 if format == "conflict" else 0), result.output
