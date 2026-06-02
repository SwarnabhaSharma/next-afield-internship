"""Click CLI for TLS 1.3 Handshake Analysis."""

import click
from .handshake import demonstrate_tls_handshake, test_connectivity
from .capture import get_instructions, parse_keylog_file, check_prerequisites
from .pfs import demonstrate_pfs, test_pfs_support, explain_pfs
from .config import (
    audit_tls_config,
    get_strong_config,
    get_nginx_config,
    get_apache_config,
)


@click.group()
def main() -> None:
    """TLS 1.3 Handshake Analysis tools."""
    pass


@main.command()
@click.option("-h", "--host", default="example.com", help="Target host")
@click.option("-p", "--port", default=443, type=int, help="Target port")
def handshake(host: str, port: int) -> None:
    """Demonstrate TLS handshake and show cipher details."""
    click.echo(f"Connecting to {host}:{port}...")
    analyzer = demonstrate_tls_handshake(host, port)
    click.echo(analyzer.get_handshake_summary())


@main.command()
def connectivity() -> None:
    """Test TLS connectivity to example.com."""
    if test_connectivity():
        click.echo("TLS connectivity: OK")
    else:
        click.echo("TLS connectivity: FAILED")


@main.command()
def capture() -> None:
    """Show instructions for capturing TLS keys."""
    click.echo(get_instructions())


@main.command()
@click.option("-f", "--file", "keylog_file", help="Keylog file to parse")
def keys(keylog_file: str) -> None:
    """Parse SSLKEYLOGFILE and show captured keys."""
    if keylog_file:
        keys = parse_keylog_file(keylog_file)
        click.echo(f"Found {len(keys)} keys in {keylog_file}")
    else:
        click.echo(get_instructions())


@main.command()
def prerequisites() -> None:
    """Check available tools for TLS capture."""
    available = check_prerequisites()
    click.echo("Available tools:")
    click.echo(f"  Wireshark: {'Yes' if available['wireshark_available'] else 'No'}")
    click.echo(f"  tshark:    {'Yes' if available['tshark_available'] else 'No'}")
    click.echo(f"  tcpdump:   {'Yes' if available['tcpdump_available'] else 'No'}")


@main.command()
def pfs_demo() -> None:
    """Demonstrate Perfect Forward Secrecy."""
    demonstrate_pfs()


@main.command()
def pfs_explain() -> None:
    """Explain Perfect Forward Secrecy."""
    click.echo(explain_pfs())


@main.command()
@click.option("-h", "--host", default="example.com", help="Server to test")
@click.option("-p", "--port", default=443, type=int, help="Port")
def pfs_test(host: str, port: int) -> None:
    """Test if server supports PFS."""
    result = test_pfs_support(host, port)
    click.echo(f"Server: {result['host']}")
    click.echo(f"PFS Supported: {result['pfs_supported']}")
    if result.get("cipher_suite"):
        click.echo(f"Cipher: {result['cipher_suite']}")
    if result.get("key_exchange"):
        click.echo(f"Key Exchange: {result['key_exchange']}")


@main.command()
@click.option("-h", "--host", required=True, help="Server to audit")
@click.option("-p", "--port", default=443, type=int, help="Port")
def audit(host: str, port: int) -> None:
    """Audit TLS configuration of a server."""
    result = audit_tls_config(host, port)

    click.echo(f"\nTLS Audit Results for {host}:{port}")
    click.echo("=" * 50)
    click.echo(f"Rating: {result.rating.value}")
    click.echo(f"Score: {result.score}/100")
    click.echo(f"Protocol: {result.protocol_version or 'N/A'}")
    click.echo(f"Cipher: {result.cipher_suite or 'N/A'}")
    click.echo(f"PFS: {'Yes' if result.pfs_enabled else 'No'}")

    if result.issues:
        click.echo("\nIssues:")
        for issue in result.issues:
            click.echo(f"  - {issue}")

    if result.recommendations:
        click.echo("\nRecommendations:")
        for rec in result.recommendations:
            click.echo(f"  - {rec}")


@main.command()
@click.option("-s", "--server", type=click.Choice(["nginx", "apache"]), default="nginx")
def config(server: str) -> None:
    """Show example TLS configuration."""
    if server == "nginx":
        click.echo(get_nginx_config())
    else:
        click.echo(get_apache_config())


@main.command()
def strong() -> None:
    """Show recommended strong TLS settings."""
    import json
    click.echo(json.dumps(get_strong_config(), indent=2))


if __name__ == "__main__":
    main()