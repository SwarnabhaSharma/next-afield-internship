"""Audit Logs - Immutable logging of all Vault operations."""

import json
from datetime import datetime
from typing import Optional, List
from .client import VaultClient


class AuditLog:
    """Vault Audit Log management."""

    def __init__(self, client: VaultClient):
        self.client = client

    def enable_file_audit(self, path: str = "/var/log/vault/audit.log") -> dict:
        """Enable file-based audit logging."""
        import requests

        headers = self.client._get_headers()

        response = requests.post(
            f"{self.client.config.address}/v1/sys/audit/file",
            json={"type": "file", "file_path": path},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def enable_syslog_audit() -> dict:
        """Enable syslog-based audit logging."""
        import requests

        from .client import VaultClient, VaultConfig
        config = VaultConfig.from_env()
        client = VaultClient(config)

        headers = client._get_headers()
        response = requests.post(
            f"{config.address}/v1/sys/audit/syslog",
            json={"type": "syslog"},
            headers=headers,
            timeout=client.config.timeout,
            verify=config.verify_ssl,
        )
        return response.json()

    def list_enabled_audit_devices(self) -> list:
        """List all enabled audit devices."""
        import requests
        headers = self.client._get_headers()

        response = requests.get(
            f"{self.client.config.address}/v1/sys/audit",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        return list(response.json()["data"].keys())

    def disable_audit(self, path: str) -> dict:
        """Disable an audit device."""
        import requests
        headers = self.client._get_headers()

        response = requests.delete(
            f"{self.client.config.address}/v1/sys/audit/{path}",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()


def enable_audit(config, device_type: str = "file", path: str = None) -> dict:
    """Convenience function to enable audit device."""
    client = VaultClient(config)
    audit = AuditLog(client)

    if device_type == "file":
        path = path or "/var/log/vault/audit.log"
        return audit.enable_file_audit(path)
    elif device_type == "syslog":
        return audit.enable_syslog_audit()

    raise ValueError(f"Unknown device type: {device_type}")


def get_audit_events(config, log_path: str = None) -> List[dict]:
    """Retrieve and parse audit log entries."""
    if log_path:
        events = []
        try:
            with open(log_path, "r") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))
        except FileNotFoundError:
            pass
        return events
    else:
        import requests
        client = VaultClient(config)
        headers = client._get_headers()

        response = requests.get(
            f"{config.address}/v1/sys/audit",
            headers=headers,
            timeout=config.timeout,
            verify=config.verify_ssl,
        )
        return list(response.json().get("data", {}).keys())


def demonstrate_audit() -> None:
    """Demonstrate Vault audit logging."""
    print("Vault Audit Logs - Immutable Operation Trail")
    print("=" * 50)

    print("""
Features:
---------
- Every request logged with auth info
- Response data included
- Tamper-evident (hash chain)
- JSON structured format
- Integrates with SIEM

Log Entry Structure:
--------------------
{
  "time": "2024-01-15T10:30:00.000Z",
  "type": "request",
  "auth": {
    "client_token": "s.Hj3...",
    "token_policies": ["default"],
    "metadata": {"role": "app-role"}
  },
  "request": {
    "operation": "read",
    "path": "secret/data/myapp",
    "client_token": "s.Hj3..."
  },
  "response": {
    "data": {...}
  }
}

Enabling Audit:
--------------
# File audit
vault audit enable file file_path=/var/log/vault/audit.log

# Syslog audit
vault audit enable syslog

# Enable with options
vault audit enable file \\
    file_path=/var/log/vault/audit.log \\
    log_raw=true
""")


class MockAuditLog:
    """Mock audit log for testing."""

    def __init__(self):
        self._entries = []

    def add_entry(self, entry_type: str, data: dict) -> None:
        import secrets
        self._entries.append({
            "time": datetime.utcnow().isoformat() + "Z",
            "type": entry_type,
            "auth": {"client_token": f"token-{secrets.token_hex(8)}"},
            "data": data,
        })

    def list_entries(self) -> List[dict]:
        return self._entries.copy()

    def enable_file_audit(self, path: str = "/var/log/vault/audit.log") -> dict:
        return {"data": {"enabled": True, "path": path}}

    def list_enabled_audit_devices(self) -> list:
        return ["file:/var/log/vault/audit.log"]