from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


@dataclass(frozen=True)
class XadesKeyPair:
    certificate_pem: str
    private_key_pem: str

    @classmethod
    def from_pem_files(
        cls,
        *,
        certificate_path: str,
        private_key_path: str,
        private_key_password: str | None = None,
    ) -> XadesKeyPair:
        cert_pem = _read_certificate_as_pem(certificate_path)
        key_pem = _read_private_key_as_unencrypted_pkcs8_pem(
            private_key_path, password=private_key_password
        )
        return cls(certificate_pem=cert_pem, private_key_pem=key_pem)

    @classmethod
    def from_pkcs12_file(
        cls,
        *,
        pkcs12_path: str,
        pkcs12_password: str | None,
    ) -> XadesKeyPair:
        return cls.from_pkcs12_bytes(
            pkcs12_bytes=Path(pkcs12_path).read_bytes(),
            pkcs12_password=pkcs12_password,
        )

    @classmethod
    def from_pkcs12_bytes(
        cls,
        *,
        pkcs12_bytes: bytes,
        pkcs12_password: str | None,
    ) -> XadesKeyPair:
        password_bytes = None if pkcs12_password is None else pkcs12_password.encode("utf-8")
        key, cert, _additional = load_key_and_certificates(pkcs12_bytes, password_bytes)
        if key is None or cert is None:
            raise ValueError("PKCS#12 does not contain both private key and certificate.")
        cert_pem = (
            cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip() + "\n"
        )
        key_pem = (
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode("utf-8")
            .strip()
            + "\n"
        )
        return cls(certificate_pem=cert_pem, private_key_pem=key_pem)


def sign_xades_enveloped(xml_string: str, certificate_pem: str, private_key_pem: str) -> str:
    try:
        import xmlsec as _xmlsec
        from lxml import etree
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("XAdES signing requires 'lxml' and 'xmlsec' extras") from exc
    xmlsec: Any = _xmlsec

    parser = etree.XMLParser(
        remove_blank_text=False,
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
    )
    doc = etree.fromstring(xml_string.encode("utf-8"), parser=parser)

    cert_pem = _ensure_pem_certificate(certificate_pem)
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    cert_digest = base64.b64encode(cert.fingerprint(hashes.SHA256())).decode("ascii")

    signature_id = "Signature"
    signed_props_id = "SignedProperties"

    public_key = cert.public_key()
    if isinstance(public_key, RSAPublicKey):
        signature_transform = xmlsec.Transform.RSA_SHA256
    elif isinstance(public_key, EllipticCurvePublicKey):
        signature_transform = xmlsec.Transform.ECDSA_SHA256
    else:  # pragma: no cover
        raise RuntimeError(f"Unsupported public key type: {type(public_key)!r}")

    signature_node = xmlsec.template.create(
        doc,
        xmlsec.Transform.EXCL_C14N,
        signature_transform,
        ns="ds",
    )
    signature_node.set("Id", signature_id)
    doc.append(signature_node)

    # Reference to the whole document (enveloped)
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA256, uri="")
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

    # XAdES SignedProperties
    # python-xmlsec exposes helpers for references/transforms/key-info, but not for ds:Object.
    # Create it manually to keep compatibility across versions.
    if hasattr(xmlsec.template, "add_object"):  # pragma: no cover
        obj = xmlsec.template.add_object(signature_node)
    else:
        obj = etree.SubElement(signature_node, f"{{{xmlsec.constants.DSigNs}}}Object")
    xades_ns = "http://uri.etsi.org/01903/v1.3.2#"
    ds_ns = xmlsec.constants.DSigNs
    qual_props = etree.SubElement(
        obj, f"{{{xades_ns}}}QualifyingProperties", nsmap={"xades": xades_ns, "ds": ds_ns}
    )
    qual_props.set("Target", f"#{signature_id}")

    signed_props = etree.SubElement(qual_props, f"{{{xades_ns}}}SignedProperties")
    signed_props.set("Id", signed_props_id)
    signed_sig_props = etree.SubElement(signed_props, f"{{{xades_ns}}}SignedSignatureProperties")

    signing_time = etree.SubElement(signed_sig_props, f"{{{xades_ns}}}SigningTime")
    signing_time.text = datetime.now(timezone.utc).isoformat()

    signing_cert = etree.SubElement(signed_sig_props, f"{{{xades_ns}}}SigningCertificate")
    cert_node = etree.SubElement(signing_cert, f"{{{xades_ns}}}Cert")
    cert_digest_node = etree.SubElement(cert_node, f"{{{xades_ns}}}CertDigest")
    digest_method = etree.SubElement(
        cert_digest_node, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod"
    )
    digest_method.set("Algorithm", xmlsec.Transform.SHA256.href)
    digest_value = etree.SubElement(
        cert_digest_node, "{http://www.w3.org/2000/09/xmldsig#}DigestValue"
    )
    digest_value.text = cert_digest

    issuer_serial = etree.SubElement(cert_node, f"{{{xades_ns}}}IssuerSerial")
    issuer_name = etree.SubElement(
        issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerName"
    )
    issuer_name.text = cert.issuer.rfc4514_string()
    serial_number = etree.SubElement(
        issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber"
    )
    serial_number.text = str(cert.serial_number)

    # Reference to SignedProperties
    ref_props = xmlsec.template.add_reference(
        signature_node,
        xmlsec.Transform.SHA256,
        uri=f"#{signed_props_id}",
        type="http://uri.etsi.org/01903#SignedProperties",
    )
    xmlsec.template.add_transform(ref_props, xmlsec.Transform.EXCL_C14N)

    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(key_info)

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_memory(private_key_pem, xmlsec.KeyFormat.PEM, None)
    ctx.key.load_cert_from_memory(cert_pem, xmlsec.KeyFormat.PEM)
    ctx.sign(signature_node)

    return etree.tostring(doc, encoding="utf-8", xml_declaration=True).decode("utf-8")


def _read_certificate_as_pem(path: str) -> str:
    raw = Path(path).read_bytes()
    if b"BEGIN CERTIFICATE" in raw:
        return raw.decode("utf-8").strip() + "\n"
    try:
        cert = x509.load_der_x509_certificate(raw)
    except Exception as exc:  # pragma: no cover
        raise ValueError(
            "Unable to load certificate. Expected PEM (`BEGIN CERTIFICATE`) or DER (`.crt`)."
        ) from exc
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip() + "\n"


def _read_private_key_as_unencrypted_pkcs8_pem(path: str, *, password: str | None) -> str:
    raw = Path(path).read_bytes()
    password_bytes = None if password is None else password.encode("utf-8")
    try:
        if b"BEGIN" in raw:
            key = load_pem_private_key(raw, password=password_bytes)
        else:
            key = load_der_private_key(raw, password=password_bytes)
    except TypeError as exc:
        raise ValueError(
            "Invalid private key password configuration. For an unencrypted key, omit the password."
        ) from exc
    except ValueError as exc:
        raise ValueError(
            "Unable to load the private key. Common causes: incorrect password or "
            "unsupported key format/encryption."
        ) from exc

    return (
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
        .strip()
        + "\n"
    )


def _ensure_pem_certificate(cert_data: str) -> str:
    if "BEGIN CERTIFICATE" in cert_data:
        return cert_data
    der = base64.b64decode(cert_data)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"
