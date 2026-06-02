"""X.509 certificate parsing and analysis."""

from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime


@dataclass
class CertificateInfo:
    """Parsed X.509 certificate information."""
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    public_key_algorithm: str
    signature_algorithm: str
    san: list[str]
    key_usage: list[str]
    is_ca: bool


def parse_certificate(cert_pem_or_der: bytes) -> CertificateInfo:
    """Parse X.509 certificate and extract key information.

    Args:
        cert_pem_or_der: PEM or DER encoded certificate

    Returns:
        CertificateInfo with parsed fields
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem_or_der, default_backend())
    except Exception:
        cert = x509.load_der_x509_certificate(cert_pem_or_der, default_backend())

    subject = ", ".join(
        f"{attr.oid._name}={attr.value}" for attr in cert.subject
    )

    issuer = ", ".join(
        f"{attr.oid._name}={attr.value}" for attr in cert.issuer
    )

    san = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [name.value for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    key_usage = []
    is_ca = False
    try:
        ku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        ku = ku_ext.value
        if ku.digital_signature:
            key_usage.append("Digital Signature")
        if ku.key_encipherment:
            key_usage.append("Key Encipherment")
        if ku.data_encipherment:
            key_usage.append("Data Encipherment")
        if ku.key_cert_sign:
            key_usage.append("Certificate Signing")
        if ku.crl_sign:
            key_usage.append("CRL Signing")
    except x509.ExtensionNotFound:
        pass

    try:
        basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        pass

    pk = cert.public_key()
    if hasattr(pk, "algorithm"):
        pk_alg = str(pk.algorithm.name)
    else:
        pk_alg = "EC"

    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        serial_number=str(cert.serial_number),
        not_valid_before=cert.not_valid_before_utc,
        not_valid_after=cert.not_valid_after_utc,
        public_key_algorithm=pk_alg,
        signature_algorithm=str(cert.signature_algorithm_oid._name),
        san=san,
        key_usage=key_usage,
        is_ca=is_ca,
    )


def parse_from_file(path: str) -> CertificateInfo:
    """Parse certificate from file."""
    with open(path, "rb") as f:
        return parse_certificate(f.read())


def format_certificate_info(info: CertificateInfo) -> str:
    """Format certificate info as readable string."""
    lines = [
        f"Subject: {info.subject}",
        f"Issuer: {info.issuer}",
        f"Serial: {info.serial_number}",
        f"Valid: {info.not_valid_before} to {info.not_valid_after}",
        f"Public Key: {info.public_key_algorithm}",
        f"Signature: {info.signature_algorithm}",
    ]
    if info.san:
        lines.append(f"SAN: {', '.join(info.san)}")
    if info.key_usage:
        lines.append(f"Key Usage: {', '.join(info.key_usage)}")
    lines.append(f"CA: {info.is_ca}")
    return "\n".join(lines)