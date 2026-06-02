"""Certificate chain verification."""

import os
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class CertificateChain:
    """Represents a certificate chain."""
    leaf: str
    intermediate: Optional[str]
    root: str

    def verify(self) -> bool:
        """Verify the chain."""
        return verify_certificate_chain(self.leaf, self.root, self.intermediate)

    def get_chain_file(self) -> str:
        """Return path to combined chain file."""
        return f"{self.leaf}.chain"


def verify_certificate_chain(
    cert_path: str,
    ca_cert_path: str,
    intermediate_cert_path: Optional[str] = None,
) -> bool:
    """Verify certificate chain using OpenSSL."""
    try:
        if intermediate_cert_path:
            cmd = [
                "openssl", "verify",
                "-CAfile", ca_cert_path,
                "-untrusted", intermediate_cert_path,
                cert_path,
            ]
        else:
            cmd = [
                "openssl", "verify",
                "-CAfile", ca_cert_path,
                cert_path,
            ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0 and "OK" in result.stdout

    except Exception:
        return False


def verify_leaf_certificate(
    leaf_cert: str,
    chain_file: str,
) -> bool:
    """Verify leaf certificate against full chain."""
    try:
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", chain_file, leaf_cert],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_certificate_info(cert_path: str) -> dict:
    """Get certificate information using OpenSSL."""
    info = {}

    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject"],
            capture_output=True,
            text=True,
        )
        info["subject"] = result.stdout.strip()

        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-issuer"],
            capture_output=True,
            text=True,
        )
        info["issuer"] = result.stdout.strip()

        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-dates"],
            capture_output=True,
            text=True,
        )
        info["dates"] = result.stdout.strip()

        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-serial"],
            capture_output=True,
            text=True,
        )
        info["serial"] = result.stdout.strip()

        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
            capture_output=True,
            text=True,
        )
        info["full_text"] = result.stdout

    except Exception as e:
        info["error"] = str(e)

    return info


def create_chain_file(leaf_path: str, intermediate_path: str, root_path: str) -> str:
    """Create a full certificate chain file."""
    chain_path = f"{leaf_path}.chain"

    with open(chain_path, "wb") as chain:
        with open(intermediate_path, "rb") as interm:
            chain.write(interm.read())
        with open(root_path, "rb") as root:
            chain.write(root.read())

    return chain_path


def demonstrate_verification() -> None:
    """Demonstrate certificate chain verification."""
    print("Certificate Chain Verification Demo")
    print("=" * 50)
    print()
    print("Command to verify:")
    print("  openssl verify -CAfile root-ca.crt -untrusted intermediate.crt server.crt")
    print()
    print("Expected output:")
    print("  server.crt: OK")
    print()
    print("Common issues:")
    print("  - Missing intermediate certificate")
    print("  - Expired certificate")
    print("  - Root CA not in trust store")
    print("  - Chain order wrong (must be leaf -> intermediate -> root)")