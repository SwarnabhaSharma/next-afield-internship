"""HashiCorp Vault - Key Management and Secrets Engine."""

from .client import VaultClient, VaultConfig
from .transit import TransitEngine, encrypt_data, decrypt_data
from .pki import PKIEngine, generate_certificate, revoke_certificate
from .dynamic import DynamicSecrets, generate_db_credentials, generate_aws_credentials
from .approle import AppRoleAuth, create_role, get_credentials
from .audit import AuditLog, enable_audit, get_audit_events

__version__ = "0.1.0"

__all__ = [
    "VaultClient",
    "VaultConfig",
    "TransitEngine",
    "encrypt_data",
    "decrypt_data",
    "PKIEngine",
    "generate_certificate",
    "revoke_certificate",
    "DynamicSecrets",
    "generate_db_credentials",
    "generate_aws_credentials",
    "AppRoleAuth",
    "create_role",
    "get_credentials",
    "AuditLog",
    "enable_audit",
    "get_audit_events",
]