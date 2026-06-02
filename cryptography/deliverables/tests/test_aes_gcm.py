"""Tests for AES-256-GCM encryption."""

import os
import tempfile
import pytest
from hypothesis import given, settings, strategies as st
from src.aes_gcm import encrypt, decrypt, derive_key, KEY_SIZE, NONCE_SIZE, TAG_SIZE
from src.aes_gcm.core import encrypt_file, decrypt_file


class TestUnit:
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(KEY_SIZE)
        plaintext = b"Hello, World!"
        ciphertext = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_wrong_key_raises(self):
        key = os.urandom(KEY_SIZE)
        wrong_key = os.urandom(KEY_SIZE)
        plaintext = b"Secret message"
        ciphertext = encrypt(plaintext, key)
        with pytest.raises(Exception):
            decrypt(ciphertext, wrong_key)

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(KEY_SIZE)
        plaintext = b"Secret message"
        ciphertext = encrypt(plaintext, key)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt(bytes(tampered), key)

    def test_ciphertext_format(self):
        key = os.urandom(KEY_SIZE)
        plaintext = b"Test"
        ciphertext = encrypt(plaintext, key)
        assert len(ciphertext) == NONCE_SIZE + len(plaintext) + TAG_SIZE

    def test_derive_key_consistency(self):
        password = "test_password_123"
        key1, salt1 = derive_key(password)
        key2, salt2 = derive_key(password, salt1)
        assert key1 == key2
        assert salt1 == salt2

    def test_different_salt_different_key(self):
        password = "test_password_123"
        key1, _ = derive_key(password)
        key2, _ = derive_key(password)
        assert key1 != key2


class TestProperty:
    @given(data=st.binary(min_size=1, max_size=1024))
    @settings(max_examples=100)
    def test_roundtrip_random_data(self, data: bytes):
        key = os.urandom(KEY_SIZE)
        ciphertext = encrypt(data, key)
        decrypted = decrypt(ciphertext, key)
        assert decrypted == data

    @given(key=st.binary(min_size=KEY_SIZE, max_size=KEY_SIZE), plaintext=st.binary(min_size=1))
    @settings(max_examples=50)
    def test_encrypt_decrypt(self, key: bytes, plaintext: bytes):
        key = key[:KEY_SIZE]
        ciphertext = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, key)
        assert decrypted == plaintext


class TestFile:
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield td

    def test_file_roundtrip(self, temp_dir: str):
        key = os.urandom(KEY_SIZE)
        plain_path = os.path.join(temp_dir, "plain.txt")
        enc_path = os.path.join(temp_dir, "encrypted.enc")
        dec_path = os.path.join(temp_dir, "decrypted.txt")

        with open(plain_path, "w") as f:
            f.write("This is a test file content!")

        encrypt_file(plain_path, enc_path, key)
        decrypt_file(enc_path, dec_path, key)

        with open(plain_path, "rb") as f1, open(dec_path, "rb") as f2:
            assert f1.read() == f2.read()

    def test_wrong_password_fails(self, temp_dir: str):
        key = os.urandom(KEY_SIZE)
        plain_path = os.path.join(temp_dir, "plain.txt")
        enc_path = os.path.join(temp_dir, "encrypted.enc")
        dec_path = os.path.join(temp_dir, "decrypted.txt")

        with open(plain_path, "w") as f:
            f.write("Secret content")

        encrypt_file(plain_path, enc_path, key)

        wrong_key = os.urandom(KEY_SIZE)
        with pytest.raises(Exception):
            decrypt_file(enc_path, dec_path, wrong_key)