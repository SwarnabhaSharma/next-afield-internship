"""Click CLI for PKI operations."""

import click
import os
from .ca import RootCA, IntermediateCA, generate_leaf_certificate, demonstrate_3tier_pki
from .extensions import createextensions, explain_extensions
from .verification import verify_certificate_chain, get_certificate_info, create_chain_file
from .config import get_step_by_step_guide, get_nginx_ssl_config, get_apache_ssl_config


@click.group()
def main() -> None:
    """PKI - 3-tier Certificate Authority with OpenSSL."""
    pass


@main.command()
@click.option("-p", "--path", default="./pki", help="PKI directory path")
def init(path: str) -> None:
    """Initialize PKI directory structure."""
    dirs = [
        os.path.join(path, "root", "private"),
        os.path.join(path, "root", "certs"),
        os.path.join(path, "intermediate", "private"),
        os.path.join(path, "intermediate", "certs"),
        os.path.join(path, "intermediate", "csr"),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    click.echo(f"Created PKI directory structure at {path}")
    click.echo("Note: Use 'pki guide' for step-by-step instructions")


@main.command()
def guide() -> None:
    """Show step-by-step PKI creation guide."""
    click.echo(get_step_by_step_guide())


@main.command()
def extensions() -> None:
    """Explain X.509 certificate extensions."""
    click.echo(explain_extensions())


@main.command()
@click.argument("cert_path")
def info(cert_path: str) -> None:
    """Show certificate information."""
    if not os.path.exists(cert_path):
        click.echo(f"Certificate not found: {cert_path}")
        return

    info = get_certificate_info(cert_path)
    for key, value in info.items():
        if key != "full_text":
            click.echo(f"{key}: {value}")


@main.command()
@click.option("-c", "--cert", required=True, help="Certificate to verify")
@click.option("-r", "--root", required=True, help="Root CA certificate")
@click.option("-i", "--intermediate", help="Intermediate CA certificate")
def verify(cert: str, root: str, intermediate: str = None) -> None:
    """Verify certificate chain."""
    result = verify_certificate_chain(cert, root, intermediate)
    if result:
        click.echo("✓ Certificate verification: OK")
    else:
        click.echo("✗ Certificate verification: FAILED")


@main.command()
@click.option("-l", "--leaf", required=True, help="Leaf certificate")
@click.option("-i", "--intermediate", required=True, help="Intermediate certificate")
@click.option("-r", "--root", required=True, help="Root CA certificate")
def chain(leaf: str, intermediate: str, root: str) -> None:
    """Create certificate chain file."""
    chain_path = create_chain_file(leaf, intermediate, root)
    click.echo(f"Created chain file: {chain_path}")
    click.echo("Use: openssl verify -CAfile <chain> <leaf>")


@main.command()
@click.option("-s", "--server", type=click.Choice(["nginx", "apache"]), default="nginx")
@click.option("-c", "--cert", required=True, help="Server certificate")
@click.option("-k", "--key", required=True, help="Server key")
@click.option("-b", "--chain", required=True, help="CA chain")
def config(server: str, cert: str, key: str, chain: str) -> None:
    """Generate web server SSL configuration."""
    if server == "nginx":
        config = get_nginx_ssl_config(cert, key, chain)
    else:
        config = get_apache_ssl_config(cert, key, chain)

    click.echo(config)


@main.command()
def demo() -> None:
    """Demonstrate 3-tier PKI creation."""
    result = demonstrate_3tier_pki()
    click.echo("\nPKI Structure:")
    for key, value in result.items():
        status = "✓ Created" if value else "✗ Skipped"
        click.echo(f"  {key}: {status}")


@main.command()
def test() -> None:
    """Test that OpenSSL is available."""
    import subprocess
    try:
        result = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
        )
        click.echo(f"OpenSSL: {result.stdout.strip()}")
    except FileNotFoundError:
        click.echo("OpenSSL not found. Install OpenSSL to use PKI features.")


if __name__ == "__main__":
    main()