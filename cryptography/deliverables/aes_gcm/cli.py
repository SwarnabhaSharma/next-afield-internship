"""Click CLI for AES-256-GCM file encryption."""

import click
import os
from .core import encrypt_file, decrypt_file
from .kdf import derive_key


@click.group()
def main() -> None:
    """AES-256-GCM authenticated file encryption."""
    pass


@main.command()
@click.option("-i", "--input", "in_file", required=True, help="Input file")
@click.option("-o", "--output", "out_file", required=True, help="Output file")
@click.option("-p", "--password", required=True, help="Encryption password")
def encrypt(in_file: str, out_file: str, password: str) -> None:
    """Encrypt a file with AES-256-GCM."""
    if not os.path.exists(in_file):
        raise click.ClickException(f"Input file not found: {in_file}")

    key, salt = derive_key(password)

    with open(out_file + ".salt", "wb") as f:
        f.write(salt)

    encrypt_file(in_file, out_file, key)
    click.echo(f"Encrypted {in_file} -> {out_file}")


@main.command()
@click.option("-i", "--input", "in_file", required=True, help="Input file")
@click.option("-o", "--output", "out_file", required=True, help="Output file")
@click.option("-p", "--password", required=True, help="Decryption password")
def decrypt(in_file: str, out_file: str, password: str) -> None:
    """Decrypt a file with AES-256-GCM."""
    if not os.path.exists(in_file):
        raise click.ClickException(f"Input file not found: {in_file}")

    salt_file = in_file + ".salt"
    if not os.path.exists(salt_file):
        raise click.ClickException(f"Salt file not found: {salt_file}")

    with open(salt_file, "rb") as f:
        salt = f.read()

    key, _ = derive_key(password, salt)

    try:
        decrypt_file(in_file, out_file, key)
        click.echo(f"Decrypted {in_file} -> {out_file}")
    except Exception as e:
        raise click.ClickException(f"Decryption failed: {e}")


if __name__ == "__main__":
    main()