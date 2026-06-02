"""Transit Secrets Engine - Encryption as a Service."""

import base64
from typing import Optional
from .client import VaultClient, VaultConfig


class TransitEngine:
    """Vault Transit Secrets Engine for encryption operations."""

    def __init__(self, client: VaultClient, mount_path: str = "transit"):
        self.client = client
        self.mount_path = mount_path

    def create_key(self, key_name: str, key_type: str = "aes256-gcm96") -> dict:
        """Create an encryption key in Transit."""
        import requests
        headers = self.client._get_headers()
        response = requests.post(
            f"{self.client.config.address}/v1/{self.mount_path}/keys/{key_name}",
            json={"type": key_type},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def list_keys(self) -> list:
        """List all encryption keys."""
        import requests
        headers = self.client._get_headers()
        response = requests.get(
            f"{self.client.config.address}/v1/{self.mount_path}/keys",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        data = response.json().get("data", {})
        return list(data.get("keys", {}).keys())

    def encrypt(self, key_name: str, plaintext: bytes) -> str:
        """Encrypt data using Transit key. Returns base64 ciphertext."""
        import requests
        headers = self.client._get_headers()
        plaintext_b64 = base64.b64encode(plaintext).decode()

        response = requests.post(
            f"{self.client.config.address}/v1/{self.mount_path}/encrypt/{key_name}",
            json={"plaintext": plaintext_b64},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        result = response.json()
        return result["data"]["ciphertext"]

    def decrypt(self, key_name: str, ciphertext: str) -> bytes:
        """Decrypt data using Transit key. Returns plaintext bytes."""
        import requests
        headers = self.client._get_headers()

        response = requests.post(
            f"{self.client.config.address}/v1/{self.mount_path}/decrypt/{key_name}",
            json={"ciphertext": ciphertext},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        result = response.json()
        plaintext_b64 = result["data"]["plaintext"]
        return base64.b64decode(plaintext_b64)

    def rotate_key(self, key_name: str) -> dict:
        """Rotate an encryption key (create new version)."""
        import requests
        headers = self.client._get_headers()
        response = requests.post(
            f"{self.client.config.address}/v1/{self.mount_path}/keys/{key_name}/rotate",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def get_key_info(self, key_name: str) -> dict:
        """Get information about an encryption key."""
        import requests
        headers = self.client._get_headers()
        response = requests.get(
            f"{self.client.config.address}/v1/{self.mount_path}/keys/{key_name}",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()


def encrypt_data(
    config: VaultConfig,
    key_name: str,
    plaintext: bytes,
    mount_path: str = "transit",
) -> str:
    """Convenience function to encrypt data."""
    client = VaultClient(config)
    engine = TransitEngine(client, mount_path)
    return engine.encrypt(key_name, plaintext)


def decrypt_data(
    config: VaultConfig,
    key_name: str,
    ciphertext: str,
    mount_path: str = "transit",
) -> bytes:
    """Convenience function to decrypt data."""
    client = VaultClient(config)
    engine = TransitEngine(client, mount_path)
    return engine.decrypt(key_name, ciphertext)


def demonstrate_transit() -> None:
    """Demonstrate Transit engine concepts."""
    print("Vault Transit - Encryption as a Service")
    print("=" * 50)

    print("""
Workflow:
---------
1. Application sends plaintext to Vault
2. Vault encrypts using managed key (app never sees key)
3. Vault returns ciphertext
4. On decrypt: app sends ciphertext, Vault returns plaintext

Benefits:
---------
- No key management burden for applications
- Keys stored securely in Vault
- Key rotation without app changes
- Audit logging of all operations
- Centralized encryption policy

Security:
---------
- Keys never leave Vault
- Encryption happens server-side
- Supports AES-GCM for authenticated encryption
- HSM backing for additional security
""")


class MockTransitEngine:
    """Mock Transit engine for testing without Vault server."""

    def __init__(self):
        self._keys = {}
        self._data = {}

    def create_key(self, key_name: str, key_type: str = "aes256-gcm96") -> dict:
        self._keys[key_name] = {"type": key_type, "versions": [1]}
        return {"data": {"name": key_name}}

    def encrypt(self, key_name: str, plaintext: bytes) -> str:
        if key_name not in self._keys:
            raise ValueError(f"Key {key_name} not found")
        ciphertext = f"vault:v1:{base64.b64encode(plaintext).decode()}"
        self._data[key_name] = ciphertext
        return ciphertext

    def decrypt(self, key_name: str, ciphertext: str) -> bytes:
        if key_name not in self._keys:
            raise ValueError(f"Key {key_name} not found")
        if not ciphertext.startswith(f"vault:v1:"):
            raise ValueError("Invalid ciphertext format")
        return base64.b64decode(ciphertext[9:])