"""Tests for TLS 1.3 Handshake Analysis module."""

import pytest
from src.tls.handshake import HandshakeAnalyzer, TLSMessageType, demonstrate_tls_handshake
from src.tls.pfs import PFS_CONFIG, NON_PFS_CONFIG, test_pfs_support
from src.tls.config import (
    get_strong_config,
    audit_tls_config,
    TLSRating,
    get_nginx_config,
    get_apache_config,
)
from src.tls.capture import parse_keylog_file, KeylogCapture, get_instructions


class TestHandshake:
    def test_analyzer_creation(self):
        analyzer = HandshakeAnalyzer()
        assert analyzer.messages == []

    def test_add_message(self):
        analyzer = HandshakeAnalyzer()
        analyzer.add_message(TLSMessageType.CLIENT_HELLO, b"test data", 0)
        assert len(analyzer.messages) == 1
        assert analyzer.messages[0].msg_type == TLSMessageType.CLIENT_HELLO

    def test_handshake_summary(self):
        analyzer = HandshakeAnalyzer()
        analyzer.add_message(TLSMessageType.CLIENT_HELLO, b"client hello", 0)
        analyzer.add_message(TLSMessageType.SERVER_HELLO, b"server hello", 1)
        analyzer.add_message(TLSMessageType.CERTIFICATE, b"cert", 2)
        summary = analyzer.get_handshake_summary()
        assert "TLS 1.3 Handshake Analysis" in summary
        assert "ClientHello" in summary
        assert "ServerHello" in summary


class TestPFS:
    def test_pfs_config_structure(self):
        assert "min_version" in PFS_CONFIG
        assert "cipher_suites" in PFS_CONFIG
        assert "ecdh_curves" in PFS_CONFIG

    def test_non_pfs_config_structure(self):
        assert "min_version" in NON_PFS_CONFIG
        assert "cipher_suites" in NON_PFS_CONFIG

    def test_pfs_config_has_ephemeral(self):
        for cipher in PFS_CONFIG["cipher_suites"]:
            assert "AES" in cipher or "CHACHA" in cipher


class TestConfig:
    def test_strong_config(self):
        config = get_strong_config()
        assert config["min_tls_version"] == "1.2"
        assert len(config["recommended_ciphers"]) > 0

    def test_nginx_config(self):
        config = get_nginx_config()
        assert "ssl_protocols" in config
        assert "TLSv1.2" in config
        assert "TLSv1.3" in config

    def test_apache_config(self):
        config = get_apache_config()
        assert "SSLProtocol" in config
        assert "SSLCipherSuite" in config

    def test_audit_returns_result(self):
        result = audit_tls_config("example.com", 443)
        assert result.rating in TLSRating
        assert isinstance(result.issues, list)
        assert isinstance(result.recommendations, list)


class TestCapture:
    def test_keylog_capture_context(self):
        with KeylogCapture("test-keys.log") as capture:
            import os
            assert os.environ.get("SSLKEYLOGFILE") == "test-keys.log"

    def test_parse_empty_keylog(self):
        keys = parse_keylog_file("/nonexistent/file.log")
        assert keys == {}

    def test_instructions_not_empty(self):
        instructions = get_instructions()
        assert len(instructions) > 0
        assert "SSLKEYLOGFILE" in instructions


class TestIntegration:
    def test_connectivity_check(self):
        result = test_pfs_support("example.com", 443)
        assert "host" in result
        assert "pfs_supported" in result

    @pytest.mark.slow
    def test_handshake_demo(self):
        analyzer = demonstrate_tls_handshake("example.com", 443)
        assert analyzer is not None