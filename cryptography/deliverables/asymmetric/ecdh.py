"""ECDH key exchange - establish shared secret without transmission."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .ecdsa import ECDSA_CURVE


def generate_ecdh_key_pair() -> tuple[bytes, bytes]:
    """Generate ECDH key pair (using P-256 curve).

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


def ecdh_key_exchange(
    private_key_pem: bytes,
    peer_public_key_pem: bytes,
    key_length: int = 32,
) -> bytes:
    """Perform ECDH key exchange to derive shared secret.

    Args:
        private_key_pem: Our private key
        peer_public_key_pem: Peer's public key
        key_length: Length of derived key in bytes (default 32)

    Returns:
        Derived shared secret key
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend(),
    )

    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_pem,
        backend=default_backend(),
    )

    from cryptography.hazmat.primitives.asymmetric import ec
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=None,
        info=b"ECDH key exchange",
        backend=default_backend(),
    )

    derived_key = hkdf.derive(shared_secret)
    return derived_key


def demonstration() -> None:
    """Demonstrate ECDH key exchange between two parties."""
    alice_private, alice_public = generate_ecdh_key_pair()
    bob_private, bob_public = generate_ecdh_key_pair()

    alice_shared = ecdh_key_exchange(alice_private, bob_public)
    bob_shared = ecdh_key_exchange(bob_private, alice_public)

    assert alice_shared == bob_shared, "Shared secrets should match!"
    print(f"ECDH demonstration successful. Shared key length: {len(alice_shared)} bytes")