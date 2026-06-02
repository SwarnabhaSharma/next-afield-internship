"""AES-256-GCM core encryption primitives."""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 64 * 1024


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM. Returns nonce || ciphertext || tag."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return nonce + ciphertext


def decrypt(ciphertext_with_tag: bytes, key: bytes) -> bytes:
    """Decrypt nonce || ciphertext || tag. Raises ValueError if auth fails."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    if len(ciphertext_with_tag) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short")

    nonce = ciphertext_with_tag[:NONCE_SIZE]
    ciphertext = ciphertext_with_tag[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_file(in_path: str, out_path: str, key: bytes) -> None:
    """Encrypt a file entirely in memory (for files under ~100MB)."""
    with open(in_path, "rb") as fin:
        plaintext = fin.read()

    ciphertext = encrypt(plaintext, key)

    with open(out_path, "wb") as fout:
        fout.write(ciphertext)


def decrypt_file(in_path: str, out_path: str, key: bytes) -> None:
    """Decrypt a file."""
    with open(in_path, "rb") as fin:
        ciphertext = fin.read()

    plaintext = decrypt(ciphertext, key)

    with open(out_path, "wb") as fout:
        fout.write(plaintext)