"""Click CLI for asymmetric cryptography operations."""

import click
import os
from .rsa import generate_rsa_key, sign_rsa, verify_rsa, save_key_pair, load_key_pair
from .ecdsa import generate_ecdsa_key, sign_ecdsa, verify_ecdsa
from .ecdh import generate_ecdh_key_pair, ecdh_key_exchange, demonstration
from .x509 import parse_from_file, format_certificate_info


@click.group()
def main() -> None:
    """Asymmetric cryptography: RSA, ECDSA, ECDH, X.509."""
    pass


@main.group()
def keygen():
    """Generate key pairs."""
    pass


@keygen.command("rsa")
@click.option("-o", "--output", default="rsa_key", help="Output prefix")
def keygen_rsa(output: str) -> None:
    """Generate RSA-4096 key pair."""
    private_pem, public_pem = generate_rsa_key()
    save_key_pair(private_pem, public_pem, output)
    click.echo(f"Generated RSA-4096 keys: {output}.private.pem, {output}.public.pem")


@keygen.command("ecdsa")
@click.option("-o", "--output", default="ecdsa_key", help="Output prefix")
def keygen_ecdsa(output: str) -> None:
    """Generate ECDSA P-256 key pair."""
    private_pem, public_pem = generate_ecdsa_key()
    with open(f"{output}.private.pem", "wb") as f:
        f.write(private_pem)
    with open(f"{output}.public.pem", "wb") as f:
        f.write(public_pem)
    click.echo(f"Generated ECDSA P-256 keys: {output}.private.pem, {output}.public.pem")


@main.group()
def sign():
    """Sign documents."""
    pass


@sign.command("rsa")
@click.option("-i", "--input", "in_file", required=True, help="File to sign")
@click.option("-k", "--key", "key_file", required=True, help="Private key file")
@click.option("-o", "--output", "out_file", required=True, help="Signature output file")
def sign_rsa_file(in_file: str, key_file: str, out_file: str) -> None:
    """Sign file with RSA-4096."""
    with open(key_file, "rb") as f:
        private_pem = f.read()
    with open(in_file, "rb") as f:
        data = f.read()

    signature = sign_rsa(data, private_pem)

    with open(out_file, "wb") as f:
        f.write(signature)
    click.echo(f"Signed {in_file} with RSA -> {out_file}")


@sign.command("ecdsa")
@click.option("-i", "--input", "in_file", required=True, help="File to sign")
@click.option("-k", "--key", "key_file", required=True, help="Private key file")
@click.option("-o", "--output", "out_file", required=True, help="Signature output file")
def sign_ecdsa_file(in_file: str, key_file: str, out_file: str) -> None:
    """Sign file with ECDSA P-256."""
    with open(key_file, "rb") as f:
        private_pem = f.read()
    with open(in_file, "rb") as f:
        data = f.read()

    signature = sign_ecdsa(data, private_pem)

    with open(out_file, "wb") as f:
        f.write(signature)
    click.echo(f"Signed {in_file} with ECDSA -> {out_file}")


@main.group()
def verify():
    """Verify signatures."""
    pass


@verify.command("rsa")
@click.option("-i", "--input", "in_file", required=True, help="Original file")
@click.option("-s", "--signature", "sig_file", required=True, help="Signature file")
@click.option("-k", "--key", "key_file", required=True, help="Public key file")
def verify_rsa_file(in_file: str, sig_file: str, key_file: str) -> None:
    """Verify RSA signature."""
    with open(key_file, "rb") as f:
        public_pem = f.read()
    with open(in_file, "rb") as f:
        data = f.read()
    with open(sig_file, "rb") as f:
        signature = f.read()

    if verify_rsa(data, signature, public_pem):
        click.echo("Signature VERIFIED")
    else:
        click.echo("Signature INVALID")


@verify.command("ecdsa")
@click.option("-i", "--input", "in_file", required=True, help="Original file")
@click.option("-s", "--signature", "sig_file", required=True, help="Signature file")
@click.option("-k", "--key", "key_file", required=True, help="Public key file")
def verify_ecdsa_file(in_file: str, sig_file: str, key_file: str) -> None:
    """Verify ECDSA signature."""
    with open(key_file, "rb") as f:
        public_pem = f.read()
    with open(in_file, "rb") as f:
        data = f.read()
    with open(sig_file, "rb") as f:
        signature = f.read()

    if verify_ecdsa(data, signature, public_pem):
        click.echo("Signature VERIFIED")
    else:
        click.echo("Signature INVALID")


@main.command()
@click.option("-c", "--certificate", required=True, help="Certificate file (PEM/DER)")
def certinfo(certificate: str) -> None:
    """Parse and display X.509 certificate info."""
    info = parse_from_file(certificate)
    click.echo(format_certificate_info(info))


@main.command()
def ecdh_demo() -> None:
    """Demonstrate ECDH key exchange."""
    demonstration()
    click.echo("ECDH key exchange demonstration complete.")


if __name__ == "__main__":
    main()