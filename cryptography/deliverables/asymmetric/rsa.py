"""RSA-4096 key generation, signing, and verification."""

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

RSA_KEY_SIZE = 4096


def generate_rsa_key() -> tuple[bytes, bytes]:
    """Generate RSA-4096 key pair.

    Returns:
        Tuple of (private_key_pem, public_key_pem).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )

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


def sign_rsa(data: bytes, private_key_pem: bytes) -> bytes:
    """Sign data with RSA-4096 using SHA-256.

    Args:
        data: Data to sign
        private_key_pem: PEM-encoded private key

    Returns:
        RSA signature
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend(),
    )

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return signature


def verify_rsa(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify RSA-4096 signature.

    Args:
        data: Original data
        signature: RSA signature
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
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def save_key_pair(private_pem: bytes, public_pem: bytes, prefix: str) -> None:
    """Save key pair to files."""
    with open(f"{prefix}.private.pem", "wb") as f:
        f.write(private_pem)
    with open(f"{prefix}.public.pem", "wb") as f:
        f.write(public_pem)


def load_key_pair(prefix: str) -> tuple[bytes, bytes]:
    """Load key pair from files."""
    with open(f"{prefix}.private.pem", "rb") as f:
        private_pem = f.read()
    with open(f"{prefix}.public.pem", "rb") as f:
        public_pem = f.read()
    return private_pem, public_pem