"""Certificate Authority implementation using OpenSSL CLI."""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class CertificateAuthority:
    """Base class for CA operations."""
    name: str
    key_path: str
    cert_path: str
    path: str

    def exists(self) -> bool:
        return os.path.exists(self.key_path) and os.path.exists(self.cert_path)

    def get_info(self) -> dict:
        """Get certificate info using openssl."""
        result = subprocess.run(
            ["openssl", "x509", "-in", self.cert_path, "-noout", "-text"],
            capture_output=True,
            text=True,
        )
        return {"output": result.stdout, "returncode": result.returncode}


class RootCA(CertificateAuthority):
    """Root Certificate Authority - offline, self-signed."""

    def __init__(self, name: str = "Root CA", base_path: str = "./pki/root"):
        self.name = name
        self.path = base_path
        self.key_path = os.path.join(base_path, "private", "ca.key.pem")
        self.cert_path = os.path.join(base_path, "certs", "ca.cert.pem")
        self.serial_path = os.path.join(base_path, "serial")
        self.index_path = os.path.join(base_path, "index.txt")

    def create(self, key_size: int = 4096, days: int = 3650) -> None:
        """Create new Root CA."""
        os.makedirs(os.path.join(self.path, "private"), exist_ok=True)
        os.makedirs(os.path.join(self.path, "certs"), exist_ok=True)

        subprocess.run([
            "openssl", "genrsa", "-out", self.key_path, str(key_size)
        ], check=True)

        subprocess.run([
            "openssl", "req", "-config", "openssl.cnf",
            "-key", self.key_path,
            "-new", "-x509",
            "-days", str(days),
            "-sha256",
            "-extensions", "v3_ca",
            "-out", self.cert_path,
            "-subj", "/CN=Root CA/O=Custom PKI/C=US",
        ], check=True)

        with open(self.serial_path, "w") as f:
            f.write("01")

        Path(self.index_path).touch()

    def sign_csr(self, csr_path: str, output_path: str, days: int = 365,
                 extensions: str = "server_ext") -> None:
        """Sign a CSR to create a certificate."""
        subprocess.run([
            "openssl", "ca", "-config", "openssl.cnf",
            "-extensions", extensions,
            "-days", str(days),
            "-notext",
            "-in", csr_path,
            "-out", output_path,
        ], check=True)


class IntermediateCA(CertificateAuthority):
    """Intermediate Certificate Authority - signed by Root CA."""

    def __init__(self, name: str = "Intermediate CA", base_path: str = "./pki/intermediate",
                 parent: Optional[RootCA] = None):
        self.name = name
        self.path = base_path
        self.parent = parent
        self.key_path = os.path.join(base_path, "private", "intermediate.key.pem")
        self.cert_path = os.path.join(base_path, "certs", "intermediate.cert.pem")
        self.csr_path = os.path.join(base_path, "csr", "intermediate.csr.pem")
        self.chain_path = os.path.join(base_path, "certs", "ca-chain.cert.pem")
        self.serial_path = os.path.join(base_path, "serial")
        self.index_path = os.path.join(base_path, "index.txt")

    def create(self, parent: RootCA, key_size: int = 4096, days: int = 1825) -> None:
        """Create new Intermediate CA signed by parent."""
        os.makedirs(os.path.join(self.path, "private"), exist_ok=True)
        os.makedirs(os.path.join(self.path, "certs"), exist_ok=True)
        os.makedirs(os.path.join(self.path, "csr"), exist_ok=True)

        subprocess.run([
            "openssl", "genrsa", "-out", self.key_path, str(key_size)
        ], check=True)

        subprocess.run([
            "openssl", "req", "-config", "openssl.cnf",
            "-new", "-sha256",
            "-key", self.key_path,
            "-out", self.csr_path,
            "-subj", "/CN=Intermediate CA/O=Custom PKI/C=US",
        ], check=True)

        parent.sign_csr(self.csr_path, self.cert_path, days, "intermediate_ca")

        with open(self.chain_path, "wb") as chain:
            with open(self.cert_path, "rb") as cert:
                chain.write(cert.read())
            with open(parent.cert_path, "rb") as root:
                chain.write(root.read())

        with open(self.serial_path, "w") as f:
            f.write("01")

        Path(self.index_path).touch()

    def get_ca_chain(self) -> str:
        """Return path to full chain (Intermediate + Root)."""
        return self.chain_path


def generate_leaf_certificate(
    common_name: str,
    san: list[str],
    intermediate: IntermediateCA,
    output_key: str,
    output_cert: str,
    days: int = 365,
) -> None:
    """Generate a leaf certificate signed by Intermediate CA."""

    subprocess.run([
        "openssl", "genrsa", "-out", output_key, "2048"
    ], check=True)

    san_str = ",".join(f"DNS:{s}" for s in san)
    subprocess.run([
        "openssl", "req", "-new", "-key", output_key,
        "-out", f"{output_cert}.csr",
        "-subj", f"/CN={common_name}/O=Custom PKI/C=US",
        "-addext", f"subjectAltName={san_str}",
    ], check=True)

    subprocess.run([
        "openssl", "ca", "-config", "openssl.cnf",
        "-extensions", "server_ext",
        "-days", str(days),
        "-notext",
        "-in", f"{output_cert}.csr",
        "-out", output_cert,
    ], check=True)

    os.remove(f"{output_cert}.csr")


def create_openssl_config(base_path: str) -> str:
    """Create openssl.cnf for the PKI."""
    config = f"""[ ca ]
default_ca = CA_default

[ CA_default ]
database = {base_path}/intermediate/index.txt
new_certs_dir = {base_path}/intermediate/certs
serial = {base_path}/intermediate/serial
private_key = {base_path}/intermediate/private/intermediate.key.pem
certificate = {base_path}/intermediate/certs/intermediate.cert.pem

default_md = sha256
policy = policy_any
copy_extensions = copy

[ policy_any ]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
string_mask = utf8only

[ req_distinguished_name ]
countryName = Country Name (2 letter code)
stateOrProvinceName = State or Province Name
localityName = Locality Name
0.organizationName = Organization Name
organizationalUnitName = Organizational Unit Name
commonName = Common Name
emailAddress = Email Address

countryName_default = US
stateOrProvinceName_default = Test State
localityName_default = Test City
0.organizationName_default = Custom PKI
emailAddress_default = admin@example.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ server_ext ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = *.local

[ client_ext ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
"""
    return config


def demonstrate_3tier_pki(base_path: str = "./pki-demo") -> dict:
    """Demonstrate creating a 3-tier PKI."""
    print("3-Tier PKI Demonstration")
    print("=" * 50)

    result = {
        "root_ca": None,
        "intermediate_ca": None,
        "leaf_cert": None,
    }

    print("Step 1: Creating Root CA...")
    root = RootCA(base_path=os.path.join(base_path, "root"))
    try:
        root.create()
        result["root_ca"] = root.cert_path
        print(f"  Root CA: {root.cert_path}")
    except Exception as e:
        print(f"  Root CA creation requires manual setup: {e}")

    print("Step 2: Creating Intermediate CA...")
    intermediate = IntermediateCA(
        base_path=os.path.join(base_path, "intermediate"),
        parent=root,
    )
    try:
        if root.exists():
            intermediate.create(root)
            result["intermediate_ca"] = intermediate.cert_path
            print(f"  Intermediate CA: {intermediate.cert_path}")
    except Exception as e:
        print(f"  Intermediate CA creation requires manual setup: {e}")

    return result