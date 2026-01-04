from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def sign_xades_enveloped(xml_string: str, certificate_pem: str, private_key_pem: str) -> str:
    try:
        from lxml import etree
        import xmlsec
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("XAdES signing requires 'lxml' and 'xmlsec' extras") from exc

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

    signature_node = xmlsec.template.create(
        doc,
        xmlsec.Transform.EXCL_C14N,
        _select_signature_transform(cert),
        ns="ds",
    )
    signature_node.set("Id", signature_id)
    doc.append(signature_node)

    # Reference to the whole document (enveloped)
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA256, uri="")
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

    # XAdES SignedProperties
    obj = xmlsec.template.add_object(signature_node)
    xades_ns = "http://uri.etsi.org/01903/v1.3.2#"
    ds_ns = xmlsec.constants.DSigNs
    qual_props = etree.SubElement(obj, f"{{{xades_ns}}}QualifyingProperties", nsmap={"xades": xades_ns, "ds": ds_ns})
    qual_props.set("Target", f"#{signature_id}")

    signed_props = etree.SubElement(qual_props, f"{{{xades_ns}}}SignedProperties")
    signed_props.set("Id", signed_props_id)
    signed_sig_props = etree.SubElement(signed_props, f"{{{xades_ns}}}SignedSignatureProperties")

    signing_time = etree.SubElement(signed_sig_props, f"{{{xades_ns}}}SigningTime")
    signing_time.text = datetime.now(timezone.utc).isoformat()

    signing_cert = etree.SubElement(signed_sig_props, f"{{{xades_ns}}}SigningCertificate")
    cert_node = etree.SubElement(signing_cert, f"{{{xades_ns}}}Cert")
    cert_digest_node = etree.SubElement(cert_node, f"{{{xades_ns}}}CertDigest")
    digest_method = etree.SubElement(cert_digest_node, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
    digest_method.set("Algorithm", xmlsec.Transform.SHA256)
    digest_value = etree.SubElement(cert_digest_node, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")
    digest_value.text = cert_digest

    issuer_serial = etree.SubElement(cert_node, f"{{{xades_ns}}}IssuerSerial")
    issuer_name = etree.SubElement(issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerName")
    issuer_name.text = cert.issuer.rfc4514_string()
    serial_number = etree.SubElement(issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber")
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


def _select_signature_transform(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if key.__class__.__name__.startswith("RSAPublicKey"):
        return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"


def _ensure_pem_certificate(cert_data: str) -> str:
    if "BEGIN CERTIFICATE" in cert_data:
        return cert_data
    der = base64.b64decode(cert_data)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"
