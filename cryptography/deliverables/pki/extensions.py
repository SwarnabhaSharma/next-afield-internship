"""X.509 Certificate Extensions for PKI."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ExtensionConfig:
    """Configuration for certificate extensions."""
    basic_constraints: str
    key_usage: list[str]
    extended_key_usage: list[str]
    subject_alt_name: list[str]
    is_ca: bool = False


SERVER_EXTENSIONS = ExtensionConfig(
    basic_constraints="CA:FALSE",
    key_usage=["critical", "digitalSignature", "keyEncipherment"],
    extended_key_usage=["serverAuth"],
    subject_alt_name=["DNS:localhost", "IP:127.0.0.1"],
    is_ca=False,
)

CLIENT_EXTENSIONS = ExtensionConfig(
    basic_constraints="CA:FALSE",
    key_usage=["critical", "nonRepudiation", "digitalSignature", "keyEncipherment"],
    extended_key_usage=["clientAuth"],
    subject_alt_name=[],
    is_ca=False,
)

CA_EXTENSIONS = ExtensionConfig(
    basic_constraints="critical, CA:true, pathlen:0",
    key_usage=["critical", "digitalSignature", "cRLSign", "keyCertSign"],
    extended_key_usage=[],
    subject_alt_name=[],
    is_ca=True,
)


ROOT_CA_EXTENSIONS = ExtensionConfig(
    basic_constraints="critical, CA:true",
    key_usage=["critical", "digitalSignature", "cRLSign", "keyCertSign"],
    extended_key_usage=[],
    subject_alt_name=[],
    is_ca=True,
)


def createextensions(ext_type: str) -> ExtensionConfig:
    """Get extension configuration by type."""
    mappings = {
        "server": SERVER_EXTENSIONS,
        "client": CLIENT_EXTENSIONS,
        "ca": CA_EXTENSIONS,
        "root_ca": ROOT_CA_EXTENSIONS,
        "intermediate": CA_EXTENSIONS,
    }
    return mappings.get(ext_type, SERVER_EXTENSIONS)


def generate_openssl_extfile(ext: ExtensionConfig, filename: str, alt_names: list[str] = None) -> None:
    """Generate OpenSSL extension file."""
    lines = []

    if ext.basic_constraints:
        lines.append(f"basicConstraints = {ext.basic_constraints}")

    if ext.key_usage:
        lines.append(f"keyUsage = {', '.join(ext.key_usage)}")

    if ext.extended_key_usage:
        lines.append(f"extendedKeyUsage = {', '.join(ext.extended_key_usage)}")

    if ext.subject_alt_name or alt_names:
        lines.append("subjectAltName = @alt_names")
        lines.append("[alt_names]")
        names = alt_names or ext.subject_alt_name
        for i, name in enumerate(names, 1):
            if name.startswith("DNS:"):
                lines.append(f"DNS.{i} = {name[4:]}")
            elif name.startswith("IP:"):
                lines.append(f"IP.{i} = {name[3:]}")

    with open(filename, "w") as f:
        f.write("\n".join(lines))


def get_common_extensions() -> dict:
    """Get common extensions used in PKI."""
    return {
        "basicConstraints": "X.509 basic constraints",
        "keyUsage": "X.509 key usage flags",
        "extendedKeyUsage": "X.509 extended key usage (serverAuth, clientAuth)",
        "subjectAltName": "Subject Alternative Names (DNS, IP, Email)",
        "subjectKeyIdentifier": "Subject Key Identifier (SHA-1 hash)",
        "authorityKeyIdentifier": "Authority Key Identifier",
        "cRLDistributionPoints": "CRL Distribution Points",
        "authorityInfoAccess": "OCSP / CA Issuers",
    }


def explain_extensions() -> str:
    """Explain X.509 certificate extensions."""
    return """
X.509 Certificate Extensions
=============================

basicConstraints
----------------
  CA:TRUE - Certificate is a CA (can sign other certs)
  CA:FALSE - End-entity certificate (leaf)
  pathlen:n - Maximum CA hierarchy depth

keyUsage
--------
  digitalSignature - Can sign data
  keyEncipherment - Can encrypt keys
  keyCertSign - Can sign certificates
  cRLSign - Can sign CRLs
  nonRepudiation - Non-repudiation (digital signature)

extendedKeyUsage
----------------
  serverAuth - TLS server authentication
  clientAuth - TLS client authentication
  emailProtection - S/MIME
  codeSigning - Code signing

subjectAltName
--------------
  DNS.1 = example.com
  DNS.2 = www.example.com
  IP.1 = 192.168.1.1
  Email = admin@example.com

CRL Distribution Points
-----------------------
  Where clients can download Certificate Revocation List

OCSP (Online Certificate Status Protocol)
------------------------------------------
  For real-time certificate revocation checking
"""