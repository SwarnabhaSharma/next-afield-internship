"""Tests for PKI module."""

import pytest
import os
from src.pki.ca import RootCA, IntermediateCA, create_openssl_config
from src.pki.extensions import (
    createextensions,
    SERVER_EXTENSIONS,
    CLIENT_EXTENSIONS,
    CA_EXTENSIONS,
    generate_openssl_extfile,
    get_common_extensions,
)
from src.pki.verification import (
    verify_certificate_chain,
    CertificateChain,
    get_certificate_info,
    create_chain_file,
    demonstrate_verification,
)
from src.pki.config import (
    get_openssl_config,
    get_root_ca_config,
    get_intermediate_config,
    get_nginx_ssl_config,
    get_apache_ssl_config,
    get_step_by_step_guide,
)


class TestExtensions:
    def test_server_extensions(self):
        ext = SERVER_EXTENSIONS
        assert ext.basic_constraints == "CA:FALSE"
        assert not ext.is_ca
        assert "serverAuth" in ext.extended_key_usage

    def test_client_extensions(self):
        ext = CLIENT_EXTENSIONS
        assert ext.basic_constraints == "CA:FALSE"
        assert "clientAuth" in ext.extended_key_usage

    def test_ca_extensions(self):
        ext = CA_EXTENSIONS
        assert ext.is_ca is True
        assert "CA:true" in ext.basic_constraints

    def test_create_extensions(self):
        ext = createextensions("server")
        assert ext.basic_constraints == "CA:FALSE"

    def test_get_common_extensions(self):
        exts = get_common_extensions()
        assert "basicConstraints" in exts
        assert "keyUsage" in exts
        assert "subjectAltName" in exts


class TestConfig:
    def test_openssl_config_generation(self):
        config = get_openssl_config("./test-ca")
        assert "[ ca ]" in config
        assert "database" in config

    def test_root_ca_config(self):
        config = get_root_ca_config("./test-ca")
        assert "v3_ca" in config

    def test_intermediate_config(self):
        config = get_intermediate_config("./test-ca")
        assert "intermediate_ca" in config

    def test_nginx_config_generation(self):
        config = get_nginx_ssl_config("server.crt", "server.key", "ca-chain.crt")
        assert "listen 443 ssl" in config
        assert "ssl_certificate" in config

    def test_apache_config_generation(self):
        config = get_apache_ssl_config("server.crt", "server.key", "ca-chain.crt")
        assert "SSLEngine on" in config
        assert "SSLCertificateFile" in config

    def test_step_by_step_guide(self):
        guide = get_step_by_step_guide()
        assert "STEP 1" in guide
        assert "STEP 2" in guide
        assert "STEP 3" in guide
        assert "STEP 4" in guide


class TestVerification:
    def test_verify_nonexistent(self):
        result = verify_certificate_chain(
            "/nonexistent/cert.pem",
            "/nonexistent/root.pem",
        )
        assert result is False

    def test_certificate_chain_class(self):
        chain = CertificateChain(
            leaf="leaf.crt",
            intermediate="intermediate.crt",
            root="root.crt",
        )
        assert chain.leaf == "leaf.crt"

    def test_get_certificate_info_missing(self):
        info = get_certificate_info("/nonexistent/cert.pem")
        assert "error" in info

    def test_demonstrate_verification(self):
        demonstrate_verification()


class TestCA:
    def test_root_ca_init(self):
        ca = RootCA(base_path="./test-pki/root")
        assert ca.name == "Root CA"
        assert "root" in ca.path

    def test_intermediate_ca_init(self):
        ca = IntermediateCA(base_path="./test-pki/intermediate")
        assert ca.name == "Intermediate CA"

    def test_openssl_config_creation(self):
        config = create_openssl_config("./test-pki")
        assert "v3_ca" in config
        assert "server_ext" in config
        assert "client_ext" in config


class TestCLI:
    def test_cli_import(self):
        from src.pki import cli
        assert cli is not None