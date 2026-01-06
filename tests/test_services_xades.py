import base64
import builtins
import sys
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from ksef_client.services import xades
from tests.helpers import generate_ec_cert, generate_rsa_cert


class DummyNode:
    def __init__(self, tag="node"):
        self.tag = tag
        self.children = []
        self.attrib = {}
        self.text = None

    def set(self, key, value):
        self.attrib[key] = value

    def append(self, node):
        self.children.append(node)


class DummyEtree(types.SimpleNamespace):
    def XMLParser(self, remove_blank_text=False, **_kwargs):
        return object()

    def fromstring(self, data, parser=None):
        return DummyNode("doc")

    def SubElement(self, parent, tag, nsmap=None):
        node = DummyNode(tag)
        parent.append(node)
        return node

    def tostring(self, doc, encoding="utf-8", xml_declaration=True):
        return b"<signed/>"


class DummyKey:
    def load_cert_from_memory(self, cert, fmt):
        return None


class DummySignatureContext:
    def __init__(self):
        self.key = None

    def sign(self, node):
        return None


class DummyTemplate:
    def __init__(self):
        self.last_transform = None

    def create(self, doc, c14n, transform, ns="ds"):
        self.last_transform = transform
        return DummyNode("Signature")

    def add_reference(self, node, transform, uri="", type=None):
        return DummyNode("Reference")

    def add_transform(self, ref, transform):
        return None

    def add_object(self, node):
        return DummyNode("Object")

    def ensure_key_info(self, node):
        return DummyNode("KeyInfo")

    def add_x509_data(self, node):
        return DummyNode("X509Data")


class DummyXmlSec(types.SimpleNamespace):
    Transform = types.SimpleNamespace(
        EXCL_C14N="c14n",
        SHA256=types.SimpleNamespace(href="sha"),
        ENVELOPED="env",
        RSA_SHA256="rsa-sha256",
        ECDSA_SHA256="ecdsa-sha256",
    )
    KeyFormat = types.SimpleNamespace(PEM="pem")
    constants = types.SimpleNamespace(DSigNs="ds")
    template = DummyTemplate()
    SignatureContext = DummySignatureContext

    class Key:
        @staticmethod
        def from_memory(key, fmt, pwd):
            return DummyKey()


class XadesTests(unittest.TestCase):
    def test_require_xades_error(self):
        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in {"lxml", "xmlsec"} or name.startswith("lxml"):
                raise ImportError("missing")
            return original_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=fake_import), self.assertRaises(RuntimeError):
            xades.sign_xades_enveloped("<xml/>", "cert", "key")

    def test_helpers(self):
        rsa_cert = generate_rsa_cert()
        pem = xades._ensure_pem_certificate(rsa_cert.certificate_pem)
        self.assertIn("BEGIN CERTIFICATE", pem)
        der = rsa_cert.certificate.public_bytes(serialization.Encoding.DER)
        b64 = base64.b64encode(der).decode("ascii")
        pem_from_der = xades._ensure_pem_certificate(b64)
        self.assertIn("BEGIN CERTIFICATE", pem_from_der)

    def test_sign_xades_with_stubs(self):
        rsa_cert = generate_rsa_cert()
        ec_cert = generate_ec_cert()
        stub_etree = DummyEtree()
        stub_xmlsec = DummyXmlSec()
        with patch.dict(
            sys.modules,
            {
                "lxml": types.SimpleNamespace(etree=stub_etree),
                "lxml.etree": stub_etree,
                "xmlsec": stub_xmlsec,
            },
        ):
            signed = xades.sign_xades_enveloped(
                "<xml/>", rsa_cert.certificate_pem, rsa_cert.private_key_pem
            )
        self.assertIn("<signed", signed)
        self.assertEqual(stub_xmlsec.template.last_transform, stub_xmlsec.Transform.RSA_SHA256)

        with patch.dict(
            sys.modules,
            {
                "lxml": types.SimpleNamespace(etree=stub_etree),
                "lxml.etree": stub_etree,
                "xmlsec": stub_xmlsec,
            },
        ):
            xades.sign_xades_enveloped("<xml/>", ec_cert.certificate_pem, ec_cert.private_key_pem)
        self.assertEqual(stub_xmlsec.template.last_transform, stub_xmlsec.Transform.ECDSA_SHA256)


if __name__ == "__main__":
    unittest.main()
