"""PKI Secrets Engine - Automated Certificate Issuance."""

from datetime import datetime, timedelta
from typing import Optional
from .client import VaultClient


class PKIEngine:
    """Vault PKI Secrets Engine for certificate management."""

    def __init__(self, client: VaultClient, mount_path: str = "pki"):
        self.client = client
        self.mount_path = mount_path

    def create_role(
        self,
        role_name: str,
        max_ttl: str = "8760h",
        allow_any_name: bool = False,
        allow_subdomains: bool = True,
        enforce_hostnames: bool = True,
        key_usage: list = None,
        ext_key_usage: list = None,
    ) -> dict:
        """Create a certificate role."""
        import requests

        if key_usage is None:
            key_usage = ["DigitalSignature", "KeyEncipherment"]
        if ext_key_usage is None:
            ext_key_usage = ["serverAuth", "clientAuth"]

        headers = self.client._get_headers()
        role_config = {
            "max_ttl": max_ttl,
            "allow_any_name": allow_any_name,
            "allow_subdomains": allow_subdomains,
            "enforce_hostnames": enforce_hostnames,
            "key_usage": key_usage,
            "ext_key_usage": ext_key_usage,
            "generate_lease": True,
            "no_store": False,
        }

        response = requests.post(
            f"{self.client.config.address}/v1/{self.mount_path}/roles/{role_name}",
            json=role_config,
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def issue_certificate(
        self,
        role_name: str,
        common_name: str,
        ttl: str = "1h",
        sans: list = None,
        format: str = "pem",
    ) -> dict:
        """Issue a certificate using a role."""
        import requests

        headers = self.client._get_headers()
        request_data = {
            "common_name": common_name,
            "ttl": ttl,
            "format": format,
        }
        if sans:
            request_data["alt_names"] = ",".join(sans)

        response = requests.post(
            f"{self.client.config.address}/v1/{self.mount_path}/issue/{role_name}",
            json=request_data,
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )

        result = response.json()
        return {
            "certificate": result["data"]["certificate"],
            "issuing_ca": result["data"]["issuing_ca"],
            "ca_chain": result["data"]["ca_chain"],
            "private_key": result["data"]["private_key"],
            "serial_number": result["data"]["serial_number"],
            "expiration": result["data"]["expiration"],
        }

    def list_certificates(self, role_name: str) -> list:
        """List certificates issued by a role."""
        import requests
        headers = self.client._get_headers()

        response = requests.list(
            f"{self.client.config.address}/v1/{self.mount_path}/certs",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json().get("data", {}).get("keys", [])

    def revoke_certificate(self, serial_number: str) -> dict:
        """Revoke a certificate by serial number."""
        import requests
        headers = self.client._get_headers()

        response = requests.post(
            f"{self.client.config.address}/v1/{self.mount_path}/revoke",
            json={"serial_number": serial_number},
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.json()

    def get_ca_certificate(self) -> str:
        """Get the CA certificate."""
        import requests
        headers = self.client._get_headers()

        response = requests.get(
            f"{self.client.config.address}/v1/{self.mount_path}/ca/pem",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.text

    def get_crl(self) -> str:
        """Get the Certificate Revocation List."""
        import requests
        headers = self.client._get_headers()

        response = requests.get(
            f"{self.client.config.address}/v1/{self.mount_path}/crl",
            headers=headers,
            timeout=self.client.config.timeout,
            verify=self.client.config.verify_ssl,
        )
        return response.content


def generate_certificate(
    config,
    role_name: str,
    common_name: str,
    ttl: str = "1h",
    sans: list = None,
) -> dict:
    """Convenience function to generate a certificate."""
    from .client import VaultClient
    client = VaultClient(config)
    engine = PKIEngine(client)
    return engine.issue_certificate(role_name, common_name, ttl, sans)


def revoke_certificate(config, serial_number: str) -> dict:
    """Convenience function to revoke a certificate."""
    from .client import VaultClient
    client = VaultClient(config)
    engine = PKIEngine(client)
    return engine.revoke_certificate(serial_number)


def demonstrate_pki() -> None:
    """Demonstrate PKI engine concepts."""
    print("Vault PKI - Automated Certificate Issuance")
    print("=" * 50)

    print("""
Workflow:
---------
1. Define certificate roles (templates)
2. Applications request certificates via API
3. Vault issues short-lived certificates (TTL)
4. Certificates auto-revoked on expiry
5. No manual certificate management

Benefits:
---------
- Short-lived certs (minutes to hours)
- Automatic renewal
- No expired certificates in production
- Centralized certificate inventory
- Built-in CRL/OCSP

Example Role:
-------------
{
  "max_ttl": "24h",
  "allow_subdomains": true,
  "key_usage": ["DigitalSignature", "KeyEncipherment"],
  "ext_key_usage": ["serverAuth"]
}

Example Issue:
--------------
vault write pki/issue web-role \\
    common_name="app.example.com" \\
    ttl="1h" \\
    alt_names="api.example.com"
""")


class MockPKIEngine:
    """Mock PKI engine for testing without Vault server."""

    def __init__(self):
        self._roles = {}
        self._certificates = {}

    def create_role(self, role_name: str, max_ttl: str = "8760h", **kwargs) -> dict:
        self._roles[role_name] = {"max_ttl": max_ttl, **kwargs}
        return {"data": {"name": role_name}}

    def issue_certificate(
        self,
        role_name: str,
        common_name: str,
        ttl: str = "1h",
        sans: list = None,
    ) -> dict:
        if role_name not in self._roles:
            raise ValueError(f"Role {role_name} not found")

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        from datetime import datetime, timedelta

        private_key = ec.generate_private_key(ec.SECP256R1())

        ttl_hours = int(ttl.rstrip("h")) if ttl.endswith("h") else 1
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(hours=ttl_hours)

        subject = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(private_key, hashes.SHA256())
        )

        serial = format(cert.serial_number, "x")

        return {
            "certificate": cert.public_bytes(Encoding.PEM).decode(),
            "private_key": private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            ).decode(),
            "serial_number": serial,
            "expiration": int(not_after.timestamp()),
        }

    def revoke_certificate(self, serial_number: str) -> dict:
        self._certificates[serial_number] = {"revoked": True, "time": datetime.utcnow()}
        return {"data": {"revocation_time": int(datetime.utcnow().timestamp())}}