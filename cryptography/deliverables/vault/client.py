"""Vault client and configuration."""

from dataclasses import dataclass
from typing import Optional
import os


@dataclass
class VaultConfig:
    """HashiCorp Vault configuration."""
    address: str
    token: str
    namespace: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "VaultConfig":
        """Load configuration from environment variables."""
        return cls(
            address=os.environ.get("VAULT_ADDR", "http://localhost:8200"),
            token=os.environ.get("VAULT_TOKEN", ""),
            namespace=os.environ.get("VAULT_NAMESPACE"),
            verify_ssl=os.environ.get("VAULT_SSL_VERIFY", "true").lower() == "true",
            timeout=int(os.environ.get("VAULT_TIMEOUT", "30")),
        )


class VaultClient:
    """Client for interacting with HashiCorp Vault."""

    def __init__(self, config: VaultConfig):
        self.config = config
        self._session = None

    def is_available(self) -> bool:
        """Check if Vault server is reachable."""
        try:
            import requests
            response = requests.get(
                f"{self.config.address}/v1/sys/health",
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
            return response.status_code in (200, 429, 503)
        except Exception:
            return False

    def health(self) -> dict:
        """Get Vault health status."""
        import requests
        response = requests.get(
            f"{self.config.address}/v1/sys/health",
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return response.json()

    def enable_secrets_engine(self, engine: str, path: str) -> dict:
        """Enable a secrets engine at a specific path."""
        import requests
        headers = self._get_headers()
        response = requests.post(
            f"{self.config.address}/v1/sys/mounts/{path}",
            json={"type": engine},
            headers=headers,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return response.json()

    def list_secrets_engines(self) -> dict:
        """List all enabled secrets engines."""
        import requests
        headers = self._get_headers()
        response = requests.get(
            f"{self.config.address}/v1/sys/mounts",
            headers=headers,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        return response.json()

    def _get_headers(self) -> dict:
        """Get headers for API requests."""
        headers = {"X-Vault-Token": self.config.token}
        if self.config.namespace:
            headers["X-Vault-Namespace"] = self.config.namespace
        return headers


def demonstrate_vault_concepts() -> str:
    """Return educational content about Vault."""
    return """
HashiCorp Vault - Key Management
=================================

Vault provides a unified interface for secrets management with:
- Encryption as a service
- Dynamic secrets
- Leases and renewal
- Revocation
- Audit logging

Core Concepts:
-------------

1. Secrets Engines
   - Transit: encryption as a service
   - PKI: certificate generation
   - KV: key-value store
   - Database: dynamic credentials
   - AWS/EC2: cloud credentials

2. Authentication
   - Token: default method
   - AppRole: machine authentication
   - Kubernetes: container auth
   - LDAP/Okta: enterprise identity

3. Authorization
   - Policies: specify allowed operations
   - Roles: group access patterns
   - Namespaces: multi-tenant isolation

4. Audit Logs
   - Immutable log of all requests
   - Includes auth, request, response
   - Integrates with SIEM tools
"""


def get_local_dev_config() -> VaultConfig:
    """Get configuration for local development."""
    return VaultConfig(
        address="http://127.0.0.1:8200",
        token="dev-token" if os.environ.get("VAULT_DEV") else "",
    )