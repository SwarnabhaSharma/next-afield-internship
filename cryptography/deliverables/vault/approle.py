"""AppRole Authentication - Machine-based authentication."""

import uuid
from typing import Optional
from .client import VaultClient


class AppRoleAuth:
    """Vault AppRole authentication for machine-to-machine auth."""

    def __init__(self, client: VaultClient, mount_path: str = "approle"):
        self.client = client
        self.mount_path = mount_path

    def create_role(
        self,
        role_name: str,
        token_ttl: str = "1h",
        token_max_ttl: str = "4h",
        policies: list = None,
        bind_secret_id: bool = True,
        secret_id_bound_cidrs: list = None,
    ) -> dict:
        """Create an AppRole role."""
        import requests

        headers = self.client._get_headers()

        role_config = {
            "token_ttl": token_ttl,
            "token_max_ttl": token_max_ttl,
            "policies": policies or ["default"],
            "bind_secret_id": bind_secret_id,
        }
        if secret_id_bound_cidrs:
            role_config["secret_id_bound_cidrs"] = secret_id_bound_cidrs

        response = requests.post(
            f"{self.client.config.address}/v1/auth/{self.mount_path}/role/{role_name}",
            json=role_config,
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def get_role_id(self, role_name: str) -> str:
        """Get the role ID for an AppRole."""
        import requests

        headers = self.client._get_headers()

        response = requests.get(
            f"{self.client.config.address}/v1/auth/{self.mount_path}/role/{role_name}/role-id",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        return response.json()["data"]["role_id"]

    def generate_secret_id(self, role_name: str, metadata: dict = None) -> str:
        """Generate a secret ID for an AppRole."""
        import requests

        headers = self.client._get_headers()

        request_data = {}
        if metadata:
            request_data["metadata"] = metadata

        response = requests.post(
            f"{self.client.config.address}/v1/auth/{self.mount_path}/role/{role_name}/secret-id",
            json=request_data,
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        return response.json()["data"]["secret_id"]

    def login(self, role_id: str, secret_id: str) -> dict:
        """Authenticate using AppRole credentials."""
        import requests

        response = requests.post(
            f"{self.client.config.address}/v1/auth/{self.mount_path}/login",
            json={
                "role_id": role_id,
                "secret_id": secret_id,
            },
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        result = response.json()
        return {
            "token": result["auth"]["client_token"],
            "token_duration": result["auth"]["lease_duration"],
            "token_policies": result["auth"]["policy"],
            "metadata": result["auth"].get("metadata"),
        }

    def revoke_secret_id(self, role_name: str, secret_id: str) -> dict:
        """Revoke a specific secret ID."""
        import requests
        headers = self.client._get_headers()

        response = requests.post(
            f"{self.client.config.address}/v1/auth/{self.mount_path}/role/{role_name}/secret-id/destroy",
            json={"secret_id": secret_id},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def list_roles(self) -> list:
        """List all AppRole roles."""
        import requests
        headers = self.client._get_headers()

        response = requests.get(
            f"{self.client.config.address}/v1/auth/{self.mount_path}/role",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        return list(response.json().get("data", {}).keys())


def create_role(config, role_name: str, policies: list = None) -> dict:
    """Convenience function to create an AppRole."""
    client = VaultClient(config)
    auth = AppRoleAuth(client)
    return auth.create_role(role_name, policies=policies)


def get_credentials(config, role_id: str, secret_id: str) -> dict:
    """Convenience function to authenticate with AppRole."""
    client = VaultClient(config)
    auth = AppRoleAuth(client)
    return auth.login(role_id, secret_id)


def demonstrate_approle() -> None:
    """Demonstrate AppRole authentication."""
    print("Vault AppRole - Machine Authentication")
    print("=" * 50)

    print("""
Workflow:
---------
1. Create AppRole with policies
2. Get role_id (static, embed in app config)
3. Generate secret_id (can be rotated)
4. App uses role_id + secret_id to login
5. Get short-lived token
6. Use token for API access

Security:
---------
- Secret ID can be bound to IP (cidr)
- Tokens auto-expire (e.g., 1 hour)
- Policies control access
- Secret IDs can be rotated
- Full audit trail

Example:
--------
# 1. Create role
vault write auth/approle/role/myapp \\
    token_ttl=1h \\
    token_max_ttl=4h \\
    policies=app-policy

# 2. Get role_id (store in app config)
vault read auth/approle/role/myapp/role-id
# Returns: role-id: 2c4a5f6d-...

# 3. Generate secret_id
vault write -f auth/approle/role/myapp/secret-id
# Returns: secret-id: 3b5a6g7h-...

# 4. Login
vault write auth/approle/login \\
    role-id=2c4a5f6d-... \\
    secret-id=3b5a6g7h-...
# Returns: client-token (use for API access)

# 5. App uses token
curl -H "X-Vault-Token: <token>" \\
    https://vault.example.com/v1/secret/data/app
""")


class MockAppRoleAuth:
    """Mock AppRole for testing."""

    def __init__(self):
        self._roles = {}
        self._secret_ids = set()

    def create_role(
        self,
        role_name: str,
        token_ttl: str = "1h",
        token_max_ttl: str = "4h",
        policies: list = None,
    ) -> dict:
        import secrets
        role_id = secrets.token_hex(16)
        self._roles[role_name] = {
            "role_id": role_id,
            "policies": policies or ["default"],
            "token_ttl": token_ttl,
        }
        return {"data": {"role_id": role_id}}

    def get_role_id(self, role_name: str) -> str:
        if role_name not in self._roles:
            raise ValueError(f"Role {role_name} not found")
        return self._roles[role_name]["role_id"]

    def generate_secret_id(self, role_name: str) -> str:
        if role_name not in self._roles:
            raise ValueError(f"Role {role_name} not found")
        import secrets
        secret_id = secrets.token_hex(16)
        self._secret_ids.add(secret_id)
        return secret_id

    def login(self, role_id: str, secret_id: str) -> dict:
        for role in self._roles.values():
            if role["role_id"] != role_id:
                continue
            if secret_id not in self._secret_ids:
                raise ValueError("Invalid secret_id")
            import secrets
            return {
                "token": f"token-{secrets.token_hex(16)}",
                "token_duration": 3600,
                "token_policies": role["policies"],
            }
        raise ValueError("Invalid role_id")