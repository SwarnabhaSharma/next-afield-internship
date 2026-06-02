"""Argon2id key derivation from password."""

import os
import base64
from argon2.low_level import hash_secret, Type as ArgonType
from .core import KEY_SIZE


def _add_padding(b64: str) -> str:
    """Add padding to base64 string that may be missing padding."""
    return b64 + "=" * (4 - len(b64) % 4)


def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a 256-bit key from password using Argon2id.

    Args:
        password: Plaintext password
        salt: Optional 16-byte salt. If None, random salt is generated.

    Returns:
        Tuple of (key, salt) where key is 32 bytes and salt is 16 bytes.
    """
    if salt is None:
        salt = os.urandom(16)

    encoded = hash_secret(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=KEY_SIZE,
        type=ArgonType.ID,
    )

    encoded_str = encoded.decode()
    parts = encoded_str.split("$")
    b64_hash = parts[-1]
    key = base64.b64decode(_add_padding(b64_hash))

    return key, salt


def verify_key(password: str, key: bytes, salt: bytes) -> bool:
    """Verify a password against a derived key."""
    derived_key, _ = derive_key(password, salt)
    return derived_key == key