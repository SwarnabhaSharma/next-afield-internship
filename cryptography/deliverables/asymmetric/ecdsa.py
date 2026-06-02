"""ECDSA P-256 signing and verification."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import os

ECDSA_CURVE = ec.SECP256R1()


def generate_ecdsa_key() -> tuple[bytes, bytes]:
    """Generate ECDSA P-256 key pair.

    Returns:
        Tuple of (private_key_pem, public_key_pem).
    """
    private_key = ec.generate_private_key(ECDSA_CURVE, default_backend())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def sign_ecdsa(data: bytes, private_key_pem: bytes) -> bytes:
    """Sign data with ECDSA P-256 using SHA-256.

    Args:
        data: Data to sign
        private_key_pem: PEM-encoded private key

    Returns:
        ECDSA signature (DER-encoded)
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend(),
    )

    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256()),
    )

    return signature


def verify_ecdsa(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify ECDSA P-256 signature.

    Args:
        data: Original data
        signature: ECDSA signature
        public_key_pem: PEM-encoded public key

    Returns:
        True if signature is valid, False otherwise
    """
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend(),
    )

    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False


def create_detached_signature(data: bytes, private_key_pem: bytes) -> bytes:
    """Create a detached signature (not embedded in data)."""
    return sign_ecdsa(data, private_key_pem)


def verify_detached_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify a detached signature."""
    return verify_ecdsa(data, signature, public_key_pem)