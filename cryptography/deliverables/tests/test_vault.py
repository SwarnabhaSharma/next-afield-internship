"""Tests for Vault module."""

import pytest
from src.vault.client import VaultConfig, demonstrate_vault_concepts, get_local_dev_config
from src.vault.transit import TransitEngine, encrypt_data, decrypt_data, demonstrate_transit, MockTransitEngine
from src.vault.pki import PKIEngine, generate_certificate, demonstrate_pki, MockPKIEngine
from src.vault.dynamic import DynamicSecrets, generate_db_credentials, demonstrate_dynamic_secrets, MockDynamicSecrets
from src.vault.approle import AppRoleAuth, create_role, get_credentials, demonstrate_approle, MockAppRoleAuth
from src.vault.audit import AuditLog, enable_audit, get_audit_events, demonstrate_audit, MockAuditLog


class TestVaultConfig:
    def test_config_from_env_missing(self):
        import os
        original = os.environ.get("VAULT_ADDR")
        if original:
            del os.environ["VAULT_ADDR"]
        config = VaultConfig.from_env()
        assert config.address == "http://localhost:8200"

    def test_config_custom_values(self):
        config = VaultConfig(
            address="https://vault.example.com",
            token="test-token",
            namespace="admin",
        )
        assert config.address == "https://vault.example.com"
        assert config.token == "test-token"
        assert config.namespace == "admin"

    def test_get_local_dev_config(self):
        config = get_local_dev_config()
        assert "127.0.0.1" in config.address


class TestTransit:
    def test_transit_engine_init(self):
        config = VaultConfig("http://localhost:8200", "test-token")
        from src.vault.client import VaultClient
        client = VaultClient(config)
        engine = TransitEngine(client)
        assert engine.mount_path == "transit"

    def test_mock_transit_create_key(self):
        mock = MockTransitEngine()
        result = mock.create_key("test-key")
        assert "test-key" in result["data"]["name"]

    def test_mock_transit_encrypt_decrypt(self):
        mock = MockTransitEngine()
        mock.create_key("test-key")
        ciphertext = mock.encrypt("test-key", b"secret data")
        plaintext = mock.decrypt("test-key", ciphertext)
        assert plaintext == b"secret data"

    def test_demonstrate_transit(self):
        demonstrate_transit()


class TestPKI:
    def test_pki_engine_init(self):
        config = VaultConfig("http://localhost:8200", "test-token")
        from src.vault.client import VaultClient
        client = VaultClient(config)
        engine = PKIEngine(client)
        assert engine.mount_path == "pki"

    def test_mock_pki_create_role(self):
        mock = MockPKIEngine()
        result = mock.create_role("web-role", "24h")
        assert "web-role" in result["data"]["name"]

    def test_mock_pki_issue_certificate(self):
        mock = MockPKIEngine()
        mock.create_role("web-role")
        result = mock.issue_certificate("web-role", "example.com", "1h")
        assert "certificate" in result
        assert "private_key" in result
        assert result["serial_number"]

    def test_mock_pki_revoke_certificate(self):
        mock = MockPKIEngine()
        mock.create_role("web-role")
        result = mock.issue_certificate("web-role", "example.com")
        revoked = mock.revoke_certificate(result["serial_number"])
        assert "revocation_time" in revoked["data"]

    def test_demonstrate_pki(self):
        demonstrate_pki()


class TestDynamicSecrets:
    def test_dynamic_secrets_init(self):
        config = VaultConfig("http://localhost:8200", "test-token")
        from src.vault.client import VaultClient
        client = VaultClient(config)
        engine = DynamicSecrets(client)
        assert engine is not None

    def test_mock_dynamic_create_role(self):
        mock = MockDynamicSecrets()
        result = mock.create_db_role("app-role", "myapp", "1h")
        assert "app-role" in result["data"]["name"]

    def test_mock_dynamic_generate_credential(self):
        mock = MockDynamicSecrets()
        mock.create_db_role("app-role", "myapp")
        result = mock.generate_db_credential("app-role")
        assert "username" in result
        assert "password" in result
        assert "lease_id" in result

    def test_mock_dynamic_revoke_lease(self):
        mock = MockDynamicSecrets()
        mock.create_db_role("app-role", "myapp")
        creds = mock.generate_db_credential("app-role")
        result = mock.revoke_lease(creds["lease_id"])
        assert result["data"]["revoked"] is True

    def test_demonstrate_dynamic(self):
        demonstrate_dynamic_secrets()


class TestAppRole:
    def test_approle_init(self):
        config = VaultConfig("http://localhost:8200", "test-token")
        from src.vault.client import VaultClient
        client = VaultClient(config)
        auth = AppRoleAuth(client)
        assert auth.mount_path == "approle"

    def test_mock_approle_create_role(self):
        mock = MockAppRoleAuth()
        result = mock.create_role("app-role", policies=["default", "app-policy"])
        role_id = result["data"]["role_id"]
        assert role_id

    def test_mock_approle_get_role_id(self):
        mock = MockAppRoleAuth()
        mock.create_role("app-role")
        role_id = mock.get_role_id("app-role")
        assert role_id

    def test_mock_approle_generate_secret(self):
        mock = MockAppRoleAuth()
        mock.create_role("app-role")
        secret_id = mock.generate_secret_id("app-role")
        assert secret_id

    def test_mock_approle_login(self):
        mock = MockAppRoleAuth()
        mock.create_role("app-role")
        role_id = mock.get_role_id("app-role")
        secret_id = mock.generate_secret_id("app-role")
        result = mock.login(role_id, secret_id)
        assert "token" in result
        assert result["token_duration"] == 3600

    def test_demonstrate_approle(self):
        demonstrate_approle()


class TestAudit:
    def test_audit_init(self):
        config = VaultConfig("http://localhost:8200", "test-token")
        from src.vault.client import VaultClient
        client = VaultClient(config)
        audit = AuditLog(client)
        assert audit is not None

    def test_mock_audit_add_entry(self):
        mock = MockAuditLog()
        mock.add_entry("request", {"path": "/secret/data/test", "operation": "read"})
        entries = mock.list_entries()
        assert len(entries) == 1
        assert entries[0]["data"]["path"] == "/secret/data/test"

    def test_mock_audit_enable(self):
        mock = MockAuditLog()
        result = mock.enable_file_audit("/var/log/vault/audit.log")
        assert result["data"]["enabled"] is True

    def test_mock_audit_list_devices(self):
        mock = MockAuditLog()
        mock.enable_file_audit("/var/log/vault/audit.log")
        devices = mock.list_enabled_audit_devices()
        assert len(devices) > 0

    def test_demonstrate_audit(self):
        demonstrate_audit()


class TestIntegration:
    def test_demonstrate_vault_concepts(self):
        content = demonstrate_vault_concepts()
        assert "Transit" in content
        assert "PKI" in content
        assert "Dynamic" in content
        assert "AppRole" in content