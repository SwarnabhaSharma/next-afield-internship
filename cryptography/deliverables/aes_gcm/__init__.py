"""AES-256-GCM authenticated file encryption."""

from .core import encrypt, decrypt, NONCE_SIZE, TAG_SIZE, KEY_SIZE
from .kdf import derive_key

__version__ = "0.1.0"

__all__ = [
    "encrypt",
    "decrypt",
    "derive_key",
    "NONCE_SIZE",
    "TAG_SIZE",
    "KEY_SIZE",
]