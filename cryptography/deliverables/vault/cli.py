"""Click CLI for HashiCorp Vault operations."""

import click
import os
from .client import VaultConfig, demonstrate_vault_concepts, get_local_dev_config
from .transit import TransitEngine, demonstrate_transit
from .pki import PKIEngine, demonstrate_pki
from .dynamic import DynamicSecrets, demonstrate_dynamic_secrets
from .approle import AppRoleAuth, demonstrate_approle
from .audit import AuditLog, demonstrate_audit


@click.group()
def main() -> None:
    """HashiCorp Vault - Key Management and Secrets."""
    pass


@main.command()
def health() -> None:
    """Check Vault server health."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)

    if client.is_available():
        health = client.health()
        click.echo(f"Vault Status: Available")
        click.echo(f"Version: {health.get('version', 'N/A')}")
        click.echo(f"Cluster ID: {health.get('cluster_id', 'N/A')}")
    else:
        click.echo("Vault Status: Not available")
        click.echo("Set VAULT_ADDR and VAULT_TOKEN environment variables")


@main.command()
def concepts() -> None:
    """Show Vault core concepts."""
    click.echo(demonstrate_vault_concepts())


@main.group()
def transit() -> None:
    """Transit secrets engine operations."""
    pass


@transit.command("create-key")
@click.argument("key_name")
@click.option("--type", "key_type", default="aes256-gcm96")
def transit_create_key(key_name: str, key_type: str) -> None:
    """Create an encryption key in Transit."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    engine = TransitEngine(client)

    try:
        result = engine.create_key(key_name, key_type)
        click.echo(f"Key '{key_name}' created successfully")
    except Exception as e:
        click.echo(f"Error: {e}")


@transit.command("encrypt")
@click.argument("key_name")
@click.argument("plaintext")
def transit_encrypt(key_name: str, plaintext: str) -> None:
    """Encrypt data using Transit."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    engine = TransitEngine(client)

    try:
        ciphertext = engine.encrypt(key_name, plaintext.encode())
        click.echo(f"Ciphertext: {ciphertext}")
    except Exception as e:
        click.echo(f"Error: {e}")


@transit.command("decrypt")
@click.argument("key_name")
@click.argument("ciphertext")
def transit_decrypt(key_name: str, ciphertext: str) -> None:
    """Decrypt data using Transit."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    engine = TransitEngine(client)

    try:
        plaintext = engine.decrypt(key_name, ciphertext)
        click.echo(f"Plaintext: {plaintext.decode()}")
    except Exception as e:
        click.echo(f"Error: {e}")


@transit.command("demo")
def transit_demo() -> None:
    """Show Transit engine demonstration."""
    demonstrate_transit()


@main.group()
def pki() -> None:
    """PKI secrets engine operations."""
    pass


@pki.command("create-role")
@click.argument("role_name")
@click.option("--max-ttl", default="8760h")
@click.option("--allow-subdomains", is_flag=True, default=True)
def pki_create_role(role_name: str, max_ttl: str, allow_subdomains: bool) -> None:
    """Create a certificate role."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    engine = PKIEngine(client)

    try:
        engine.create_role(role_name, max_ttl, allow_subdomains=allow_subdomains)
        click.echo(f"Role '{role_name}' created")
    except Exception as e:
        click.echo(f"Error: {e}")


@pki.command("issue")
@click.argument("role_name")
@click.argument("common_name")
@click.option("--ttl", default="1h")
def pki_issue(role_name: str, common_name: str, ttl: str) -> None:
    """Issue a certificate."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    engine = PKIEngine(client)

    try:
        result = engine.issue_certificate(role_name, common_name, ttl)
        click.echo(f"Certificate issued:")
        click.echo(f"  Serial: {result['serial_number']}")
        click.echo(f"  Expiration: {result['expiration']}")
    except Exception as e:
        click.echo(f"Error: {e}")


@pki.command("demo")
def pki_demo() -> None:
    """Show PKI engine demonstration."""
    demonstrate_pki()


@main.group()
def dynamic() -> None:
    """Dynamic secrets operations."""
    pass


@dynamic.command("demo")
def dynamic_demo() -> None:
    """Show dynamic secrets demonstration."""
    demonstrate_dynamic_secrets()


@main.group()
def approle() -> None:
    """AppRole authentication operations."""
    pass


@approle.command("create-role")
@click.argument("role_name")
@click.option("--policies", multiple=True, default=("default",))
@click.option("--token-ttl", default="1h")
def approle_create_role(role_name: str, policies: tuple, token_ttl: str) -> None:
    """Create an AppRole role."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    auth = AppRoleAuth(client)

    try:
        result = auth.create_role(role_name, policies=list(policies), token_ttl=token_ttl)
        role_id = result.get("data", {}).get("role_id", "N/A")
        click.echo(f"Role '{role_name}' created")
        click.echo(f"  Role ID: {role_id}")
    except Exception as e:
        click.echo(f"Error: {e}")


@approle.command("demo")
def approle_demo() -> None:
    """Show AppRole demonstration."""
    demonstrate_approle()


@main.group()
def audit() -> None:
    """Audit log operations."""
    pass


@audit.command("enable")
@click.option("--type", "device_type", default="file", type=click.Choice(["file", "syslog"]))
@click.option("--path", default="/var/log/vault/audit.log")
def audit_enable(device_type: str, path: str) -> None:
    """Enable audit logging."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    audit = AuditLog(client)

    try:
        if device_type == "file":
            result = audit.enable_file_audit(path)
        else:
            result = audit.enable_syslog_audit()
        click.echo(f"Audit device enabled: {device_type}")
    except Exception as e:
        click.echo(f"Error: {e}")


@audit.command("list")
def audit_list() -> None:
    """List enabled audit devices."""
    config = VaultConfig.from_env()
    from .client import VaultClient
    client = VaultClient(config)
    audit = AuditLog(client)

    try:
        devices = audit.list_enabled_audit_devices()
        click.echo("Enabled audit devices:")
        for device in devices:
            click.echo(f"  - {device}")
    except Exception as e:
        click.echo(f"Error: {e}")


@audit.command("demo")
def audit_demo() -> None:
    """Show audit log demonstration."""
    demonstrate_audit()


@main.command()
def demo() -> None:
    """Show Vault concepts demonstration."""
    click.echo(demonstrate_vault_concepts())


if __name__ == "__main__":
    main()