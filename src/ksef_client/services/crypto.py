from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import BinaryIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from ..models import EncryptionInfo, FileMetadata


@dataclass(frozen=True)
class EncryptionData:
    key: bytes
    iv: bytes
    encryption_info: EncryptionInfo


def _load_certificate(cert_data: str | bytes) -> x509.Certificate:
    data = cert_data if isinstance(cert_data, bytes) else cert_data.encode("ascii")
    if b"BEGIN CERTIFICATE" in data:
        return x509.load_pem_x509_certificate(data)
    try:
        der = base64.b64decode(data)
        return x509.load_der_x509_certificate(der)
    except Exception:
        return x509.load_pem_x509_certificate(data)


def _load_public_key_from_cert(cert_data: str | bytes):
    cert = _load_certificate(cert_data)
    return cert.public_key()


def _load_private_key(key_data: str | bytes, password: bytes | None = None):
    if isinstance(key_data, str):
        key_data = key_data.encode("ascii")
    if b"BEGIN" in key_data:
        return serialization.load_pem_private_key(key_data, password=password)
    der = base64.b64decode(key_data)
    return serialization.load_der_private_key(der, password=password)


def generate_symmetric_key() -> bytes:
    return os.urandom(32)


def generate_iv() -> bytes:
    return os.urandom(16)


def encrypt_aes_cbc_pkcs7(data: bytes, key: bytes, iv: bytes) -> bytes:
    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_aes_cbc_pkcs7(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def sha256_base64(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return base64.b64encode(digest.finalize()).decode("ascii")


def get_file_metadata(data: bytes) -> FileMetadata:
    return FileMetadata(file_size=len(data), sha256_base64=sha256_base64(data))


def get_stream_metadata(stream: BinaryIO) -> FileMetadata:
    position = None
    try:
        if stream.seekable():
            position = stream.tell()
            stream.seek(0)
    except Exception:
        position = None

    digest = hashes.Hash(hashes.SHA256())
    size = 0
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        size += len(chunk)
        digest.update(chunk)

    if position is not None:
        stream.seek(position)

    return FileMetadata(
        file_size=size, sha256_base64=base64.b64encode(digest.finalize()).decode("ascii")
    )


def build_encryption_data(public_certificate: str | bytes) -> EncryptionData:
    key = generate_symmetric_key()
    iv = generate_iv()
    encrypted_key = encrypt_rsa_oaep(public_certificate, key)
    encryption_info = EncryptionInfo(
        encrypted_symmetric_key=base64.b64encode(encrypted_key).decode("ascii"),
        initialization_vector=base64.b64encode(iv).decode("ascii"),
    )
    return EncryptionData(key=key, iv=iv, encryption_info=encryption_info)


def encrypt_rsa_oaep(public_certificate: str | bytes, data: bytes) -> bytes:
    public_key = _load_public_key_from_cert(public_certificate)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("RSA public key required")
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )


def encrypt_ksef_token_rsa(public_certificate: str | bytes, token: str, timestamp_ms: int) -> bytes:
    payload = f"{token}|{timestamp_ms}".encode()
    return encrypt_rsa_oaep(public_certificate, payload)


def encrypt_ksef_token_ec(
    public_certificate: str | bytes,
    token: str,
    timestamp_ms: int,
    *,
    output_format: str = "java",
) -> bytes:
    payload = f"{token}|{timestamp_ms}".encode()
    public_key = _load_public_key_from_cert(public_certificate)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("ECDSA public key required")

    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    aes_key = shared_secret[:32]

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, payload, None)

    ephemeral_public_key = ephemeral_private_key.public_key()
    spki = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if output_format.lower() == "csharp":
        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]
        return spki + nonce + tag + ciphertext

    if output_format.lower() == "java":
        return spki + nonce + ciphertext_with_tag

    raise ValueError("Unsupported output_format: use 'java' or 'csharp'")


def build_send_invoice_request(
    invoice_xml: bytes,
    key: bytes,
    iv: bytes,
    *,
    offline_mode: bool | None = None,
    hash_of_corrected_invoice: str | None = None,
) -> dict[str, object]:
    invoice_hash = sha256_base64(invoice_xml)
    encrypted_content = encrypt_aes_cbc_pkcs7(invoice_xml, key, iv)
    encrypted_hash = sha256_base64(encrypted_content)
    request: dict[str, object] = {
        "invoiceHash": invoice_hash,
        "invoiceSize": len(invoice_xml),
        "encryptedInvoiceHash": encrypted_hash,
        "encryptedInvoiceSize": len(encrypted_content),
        "encryptedInvoiceContent": base64.b64encode(encrypted_content).decode("ascii"),
    }
    if offline_mode is not None:
        request["offlineMode"] = offline_mode
    if hash_of_corrected_invoice:
        request["hashOfCorrectedInvoice"] = hash_of_corrected_invoice
    return request


def sign_path_rsa_pss(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def sign_path_ecdsa(
    private_key: ec.EllipticCurvePrivateKey, data: bytes, *, format: str = "p1363"
) -> bytes:
    signature_der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    if format.lower() == "der":
        return signature_der

    # Convert DER signature to P1363 (r || s)
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(signature_der)
    size = (private_key.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def load_private_key(private_key_data: str | bytes, password: bytes | None = None):
    return _load_private_key(private_key_data, password=password)
