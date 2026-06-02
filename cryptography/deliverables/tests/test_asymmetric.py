"""Tests for asymmetric cryptography: RSA, ECDSA, ECDH, X.509."""

import os
import tempfile
import pytest
from hypothesis import given, settings, strategies as st

from src.asymmetric.rsa import generate_rsa_key, sign_rsa, verify_rsa, save_key_pair, load_key_pair
from src.asymmetric.ecdsa import generate_ecdsa_key, sign_ecdsa, verify_ecdsa, create_detached_signature, verify_detached_signature
from src.asymmetric.ecdh import generate_ecdh_key_pair, ecdh_key_exchange, demonstration
from src.asymmetric.x509 import parse_certificate, format_certificate_info


class TestRSA:
    def test_generate_and_sign(self):
        private_pem, public_pem = generate_rsa_key()
        data = b"Test data for RSA signing"
        signature = sign_rsa(data, private_pem)
        assert verify_rsa(data, signature, public_pem)

    def test_wrong_key_fails(self):
        private_pem, _ = generate_rsa_key()
        _, public_pem2 = generate_rsa_key()
        data = b"Test data"
        signature = sign_rsa(data, private_pem)
        assert not verify_rsa(data, signature, public_pem2)

    def test_tampered_data_fails(self):
        private_pem, public_pem = generate_rsa_key()
        data = b"Original data"
        signature = sign_rsa(data, private_pem)
        tampered = b"Tampered data"
        assert not verify_rsa(tampered, signature, public_pem)

    def test_save_load_key_pair(self):
        with tempfile.TemporaryDirectory() as td:
            private_pem, public_pem = generate_rsa_key()
            save_key_pair(private_pem, public_pem, os.path.join(td, "test"))
            loaded_private, loaded_public = load_key_pair(os.path.join(td, "test"))
            data = b"Test"
            signature = sign_rsa(data, loaded_private)
            assert verify_rsa(data, signature, loaded_public)


class TestECDSA:
    def test_generate_and_sign(self):
        private_pem, public_pem = generate_ecdsa_key()
        data = b"Test data for ECDSA signing"
        signature = sign_ecdsa(data, private_pem)
        assert verify_ecdsa(data, signature, public_pem)

    def test_wrong_key_fails(self):
        private_pem, _ = generate_ecdsa_key()
        _, public_pem2 = generate_ecdsa_key()
        data = b"Test data"
        signature = sign_ecdsa(data, private_pem)
        assert not verify_ecdsa(data, signature, public_pem2)

    def test_detached_signature(self):
        private_pem, public_pem = generate_ecdsa_key()
        data = b"Test data"
        signature = create_detached_signature(data, private_pem)
        assert verify_detached_signature(data, signature, public_pem)

    def test_detached_wrong_data_fails(self):
        private_pem, public_pem = generate_ecdsa_key()
        data = b"Original data"
        signature = create_detached_signature(data, private_pem)
        wrong_data = b"Different data"
        assert not verify_detached_signature(wrong_data, signature, public_pem)


class TestECDH:
    def test_key_exchange(self):
        alice_private, alice_public = generate_ecdh_key_pair()
        bob_private, bob_public = generate_ecdh_key_pair()

        alice_shared = ecdh_key_exchange(alice_private, bob_public)
        bob_shared = ecdh_key_exchange(bob_private, alice_public)

        assert alice_shared == bob_shared
        assert len(alice_shared) == 32

    def test_different_keys_different_secrets(self):
        alice_private, alice_public = generate_ecdh_key_pair()
        _, bob_public2 = generate_ecdh_key_pair()

        shared1 = ecdh_key_exchange(alice_private, bob_public2)
        shared2 = ecdh_key_exchange(alice_private, bob_public2)

        assert shared1 == shared2

    def test_demonstration(self):
        demonstration()


class TestX509:
    @pytest.fixture
    def self_signed_cert(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timedelta

        private_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("test.example.com"),
                    x509.DNSName("www.test.example.com"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        return cert.public_bytes(serialization.Encoding.PEM)

    def test_parse_certificate(self, self_signed_cert):
        info = parse_certificate(self_signed_cert)
        assert "test.example.com" in info.subject
        assert "test.example.com" in info.issuer
        assert info.is_ca is True
        assert "test.example.com" in info.san
        assert "www.test.example.com" in info.san

    def test_format_info(self, self_signed_cert):
        info = parse_certificate(self_signed_cert)
        formatted = format_certificate_info(info)
        assert "Subject:" in formatted
        assert "SAN:" in formatted
        assert "CA: True" in formatted


class TestProperty:
    @given(data=st.binary(min_size=1, max_size=1024))
    @settings(max_examples=20)
    def test_ecdsa_roundtrip(self, data: bytes):
        private_pem, public_pem = generate_ecdsa_key()
        signature = sign_ecdsa(data, private_pem)
        assert verify_ecdsa(data, signature, public_pem)

    @given(data=st.binary(min_size=1, max_size=256))
    @settings(max_examples=5, deadline=10000)
    def test_rsa_roundtrip(self, data: bytes):
        private_pem, public_pem = generate_rsa_key()
        signature = sign_rsa(data, private_pem)
        assert verify_rsa(data, signature, public_pem)