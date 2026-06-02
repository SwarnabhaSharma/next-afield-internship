"""Dynamic Secrets - Short-lived credentials with automatic rotation."""

from typing import Optional
from datetime import datetime, timedelta
from .client import VaultClient


class DynamicSecrets:
    """Vault Dynamic Secrets for on-demand credential generation."""

    def __init__(self, client: VaultClient):
        self.client = client

    def configure_database(
        self,
        name: str,
        plugin: str = "postgresql-database-plugin",
        connection_url: str = None,
        allowed_roles: list = None,
    ) -> dict:
        """Configure a database secrets engine."""
        import requests

        headers = self.client._get_headers()
        config = {
            "plugin_name": plugin,
            "allowed_roles": allowed_roles or ["*"],
        }
        if connection_url:
            config["connection_url"] = connection_url

        response = requests.post(
            f"{self.client.config.address}/v1/database/config/{name}",
            json=config,
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def create_db_role(
        self,
        name: str,
        db_name: str,
        default_ttl: str = "1h",
        max_ttl: str = "24h",
        creation_statements: list = None,
    ) -> dict:
        """Create a database role."""
        import requests

        headers = self.client._get_headers()
        if creation_statements is None:
            creation_statements = [
                'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\';',
                'GRANT ALL PRIVILEGES ON DATABASE "{{database}}" TO "{{name}}";',
            ]

        role_config = {
            "db_name": db_name,
            "default_ttl": default_ttl,
            "max_ttl": max_ttl,
            "creation_statements": creation_statements,
        }

        response = requests.post(
            f"{self.client.config.address}/v1/database/roles/{name}",
            json=role_config,
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def generate_db_credential(self, role_name: str) -> dict:
        """Generate dynamic database credentials."""
        import requests

        headers = self.client._get_headers()

        response = requests.get(
            f"{self.client.config.address}/v1/database/creds/{role_name}",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        result = response.json()
        return {
            "username": result["data"]["username"],
            "password": result["data"]["password"],
            "lease_id": result["lease_id"],
            "lease_duration": result["lease_duration"],
            "renewable": result.get("renewable", False),
        }

    def revoke_lease(self, lease_id: str) -> dict:
        """Revoke a dynamic credential lease."""
        import requests

        headers = self.client._get_headers()

        response = requests.post(
            f"{self.client.config.address}/v1/sys/leases/revoke",
            json={"lease_id": lease_id},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def renew_lease(self, lease_id: str, increment: int = 3600) -> dict:
        """Renew a dynamic credential lease."""
        import requests

        headers = self.client._get_headers()

        response = requests.post(
            f"{self.client.config.address}/v1/sys/leases/renew",
            json={"lease_id": lease_id, "increment": increment},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()


def generate_db_credentials(config, role_name: str) -> dict:
    """Convenience function to generate DB credentials."""
    client = VaultClient(config)
    engine = DynamicSecrets(client)
    return engine.generate_db_credential(role_name)


def generate_aws_credentials(
    config,
    role_name: str,
    ttl: str = "1h",
) -> dict:
    """Generate dynamic AWS credentials."""
    import requests
    client = VaultClient(config)
    headers = client._get_headers()

    response = requests.get(
        f"{config.address}/v1/aws/creds/{role_name}",
        json={"ttl": ttl},
        headers=headers,
        timeout=client.config.timeout,
        verify=config.verify_ssl,
    )

    result = response.json()
    return {
        "access_key": result["data"]["access_key"],
        "secret_key": result["data"]["secret_key"],
        "security_token": result["data"].get("security_token"),
        "lease_id": result["lease_id"],
    }


def demonstrate_dynamic_secrets() -> None:
    """Demonstrate dynamic secrets concepts."""
    print("Vault Dynamic Secrets - On-Demand Credentials")
    print("=" * 50)

    print("""
Workflow:
---------
1. Configure database connection in Vault
2. Define roles with SQL creation statements
3. App requests credentials via API
4. Vault generates unique username/password
5. Lease issued with TTL (e.g., 1 hour)
6. App uses credentials, renews as needed
7. After TTL, credentials auto-revoked

Benefits:
---------
- No static credentials in configuration
- Unique credentials per request
- Automatic rotation on expiry
- Short-lived = reduced blast radius
- Centralized audit trail

Example:
--------
# Configure PostgreSQL
vault write database/config/myapp \\
    plugin_name=postgresql-database-plugin \\
    connection_url="postgresql://user:pass@localhost:5432/db"

# Create role
vault write database/roles/app-role \\
    db_name=myapp \\
    default_ttl=1h \\
    max_ttl=24h \\
    creation_statements="CREATE ROLE..."

# Get credentials
vault read database/creds/app-role

# Returns:
# - username: v-token-user-abc123
# - password: random-password
# - lease_duration: 3600
""")


class MockDynamicSecrets:
    """Mock dynamic secrets for testing."""

    def __init__(self):
        self._roles = {}
        self._credentials = {}

    def create_db_role(
        self,
        name: str,
        db_name: str,
        default_ttl: str = "1h",
        max_ttl: str = "24h",
    ) -> dict:
        self._roles[name] = {"db_name": db_name, "ttl": default_ttl}
        return {"data": {"name": name}}

    def generate_db_credential(self, role_name: str) -> dict:
        if role_name not in self._roles:
            raise ValueError(f"Role {role_name} not found")

        import secrets
        import string

        username = f"v_token_{secrets.token_hex(8)}"
        password = "".join(
            secrets.choice(string.ascii_letters + string.digits)
            for _ in range(32)
        )

        lease_id = f"database/creds/{role_name}/{secrets.token_hex(8)}"

        self._credentials[lease_id] = {
            "username": username,
            "password": password,
            "role": role_name,
            "created": datetime.utcnow(),
        }

        return {
            "username": username,
            "password": password,
            "lease_id": lease_id,
            "lease_duration": 3600,
            "renewable": True,
        }

    def revoke_lease(self, lease_id: str) -> dict:
        if lease_id in self._credentials:
            del self._credentials[lease_id]
        return {"data": {"revoked": True}}