import base64
import io
import unittest
from typing import BinaryIO, cast
from unittest.mock import patch

from ksef_client.services import crypto
from ksef_client.services.crypto import (
    build_send_invoice_request,
    decrypt_aes_cbc_pkcs7,
    encrypt_aes_cbc_pkcs7,
    generate_iv,
    generate_symmetric_key,
)
from tests.helpers import generate_ec_cert, generate_rsa_cert


class CryptoTests(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        payload = b"sample payload"
        encrypted = encrypt_aes_cbc_pkcs7(payload, key, iv)
        decrypted = decrypt_aes_cbc_pkcs7(encrypted, key, iv)
        self.assertEqual(decrypted, payload)

    def test_build_send_invoice_request(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        payload = b"<Invoice></Invoice>"
        request = build_send_invoice_request(payload, key, iv)
        self.assertIn("encryptedInvoiceContent", request)
        self.assertEqual(request["invoiceSize"], len(payload))

    def test_generate_lengths(self):
        self.assertEqual(len(generate_symmetric_key()), 32)
        self.assertEqual(len(generate_iv()), 16)

    def test_metadata_helpers(self):
        data = b"data"
        meta = crypto.get_file_metadata(data)
        self.assertEqual(meta.file_size, 4)
        self.assertEqual(meta.sha256_base64, crypto.sha256_base64(data))

        stream = io.BytesIO(data)
        stream_meta = crypto.get_stream_metadata(stream)
        self.assertEqual(stream_meta.file_size, 4)
        self.assertEqual(stream.read(), data)

        class NonSeekable:
            def __init__(self, payload: bytes) -> None:
                self._buf = io.BytesIO(payload)

            def read(self, size: int = -1) -> bytes:
                return self._buf.read(size)

            def seekable(self) -> bool:
                return False

        non_seek = NonSeekable(data)
        non_seek_meta = crypto.get_stream_metadata(cast(BinaryIO, non_seek))
        self.assertEqual(non_seek_meta.file_size, 4)

        class SeekError:
            def __init__(self, payload: bytes) -> None:
                self._buf = io.BytesIO(payload)

            def read(self, size: int = -1) -> bytes:
                return self._buf.read(size)

            def seekable(self) -> bool:
                raise OSError("nope")

        seek_error = SeekError(data)
        seek_error_meta = crypto.get_stream_metadata(cast(BinaryIO, seek_error))
        self.assertEqual(seek_error_meta.file_size, 4)

    def test_certificate_loading(self):
        rsa_cert = generate_rsa_cert()
        cert_from_pem = crypto._load_certificate(rsa_cert.certificate_pem)
        cert_from_der = crypto._load_certificate(rsa_cert.certificate_der_b64)
        cert_from_bytes = crypto._load_certificate(rsa_cert.certificate_pem.encode("ascii"))
        self.assertEqual(cert_from_pem.serial_number, rsa_cert.certificate.serial_number)
        self.assertEqual(cert_from_der.serial_number, rsa_cert.certificate.serial_number)
        self.assertEqual(cert_from_bytes.serial_number, rsa_cert.certificate.serial_number)

        with (
            patch(
                "ksef_client.services.crypto.x509.load_der_x509_certificate",
                side_effect=ValueError,
            ),
            patch(
                "ksef_client.services.crypto.x509.load_pem_x509_certificate",
                return_value=rsa_cert.certificate,
            ),
        ):
            cert_fallback = crypto._load_certificate(rsa_cert.certificate_der_b64)
        self.assertEqual(cert_fallback.serial_number, rsa_cert.certificate.serial_number)

    def test_private_key_loading(self):
        rsa_cert = generate_rsa_cert()
        key = crypto._load_private_key(rsa_cert.private_key_pem)
        self.assertEqual(key.key_size, rsa_cert.private_key.key_size)
        key_from_bytes = crypto._load_private_key(rsa_cert.private_key_pem.encode("ascii"))
        self.assertEqual(key_from_bytes.key_size, rsa_cert.private_key.key_size)
        der = rsa_cert.private_key.private_bytes(
            encoding=crypto.serialization.Encoding.DER,
            format=crypto.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto.serialization.NoEncryption(),
        )
        key_from_der = crypto._load_private_key(base64.b64encode(der).decode("ascii"))
        self.assertEqual(key_from_der.key_size, rsa_cert.private_key.key_size)

    def test_build_encryption_data(self):
        rsa_cert = generate_rsa_cert()
        encryption = crypto.build_encryption_data(rsa_cert.certificate_pem)
        self.assertEqual(len(encryption.key), 32)
        self.assertEqual(len(encryption.iv), 16)
        self.assertTrue(encryption.encryption_info.encrypted_symmetric_key)

    def test_encrypt_rsa_oaep(self):
        rsa_cert = generate_rsa_cert()
        encrypted = crypto.encrypt_rsa_oaep(rsa_cert.certificate_pem, b"data")
        self.assertTrue(encrypted)
        ec_cert = generate_ec_cert()
        with self.assertRaises(ValueError):
            crypto.encrypt_rsa_oaep(ec_cert.certificate_pem, b"data")

    def test_encrypt_ksef_token(self):
        rsa_cert = generate_rsa_cert()
        encrypted = crypto.encrypt_ksef_token_rsa(rsa_cert.certificate_pem, "token", 1)
        self.assertTrue(encrypted)

        ec_cert = generate_ec_cert()
        encrypted_java = crypto.encrypt_ksef_token_ec(
            ec_cert.certificate_pem, "token", 1, output_format="java"
        )
        encrypted_csharp = crypto.encrypt_ksef_token_ec(
            ec_cert.certificate_pem, "token", 1, output_format="csharp"
        )
        self.assertNotEqual(encrypted_java, encrypted_csharp)

        with self.assertRaises(ValueError):
            crypto.encrypt_ksef_token_ec(rsa_cert.certificate_pem, "token", 1)
        with self.assertRaises(ValueError):
            crypto.encrypt_ksef_token_ec(
                ec_cert.certificate_pem, "token", 1, output_format="unknown"
            )

    def test_build_send_invoice_optional_fields(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        payload = b"<Invoice></Invoice>"
        request = build_send_invoice_request(
            payload,
            key,
            iv,
            offline_mode=True,
            hash_of_corrected_invoice="hash",
        )
        self.assertTrue(request["offlineMode"])
        self.assertEqual(request["hashOfCorrectedInvoice"], "hash")

    def test_signatures(self):
        rsa_cert = generate_rsa_cert()
        signature = crypto.sign_path_rsa_pss(rsa_cert.private_key, b"data")
        self.assertTrue(signature)

        ec_cert = generate_ec_cert()
        sig_p1363 = crypto.sign_path_ecdsa(ec_cert.private_key, b"data")
        sig_der = crypto.sign_path_ecdsa(ec_cert.private_key, b"data", format="der")
        self.assertNotEqual(sig_p1363, sig_der)

    def test_load_private_key_wrapper(self):
        rsa_cert = generate_rsa_cert()
        key = crypto.load_private_key(rsa_cert.private_key_pem)
        self.assertEqual(key.key_size, rsa_cert.private_key.key_size)


if __name__ == "__main__":
    unittest.main()
