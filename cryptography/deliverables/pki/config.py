"""OpenSSL configuration templates for PKI."""

from typing import Optional


def get_openssl_config(
    ca_path: str,
    default_bits: int = 2048,
    default_md: str = "sha256",
) -> str:
    """Generate OpenSSL config for a CA."""
    return f"""# OpenSSL configuration for PKI

[ ca ]
default_ca = CA_default

[ CA_default ]
database = {ca_path}/index.txt
new_certs_dir = {ca_path}/certs
serial = {ca_path}/serial
private_key = {ca_path}/private/ca.key
certificate = {ca_path}/certs/ca.crt

default_md = {default_md}
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

countryName_default = US
stateOrProvinceName_default = California
localityName_default = San Francisco
0.organizationName_default = Custom PKI

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

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
IP.1 = 127.0.0.1

[ client_ext ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
"""


def get_root_ca_config(ca_path: str) -> str:
    """Get configuration for Root CA."""
    return get_openssl_config(ca_path)


def get_intermediate_config(ca_path: str) -> str:
    """Get configuration for Intermediate CA."""
    config = get_openssl_config(ca_path)
    config += """

[ intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""
    return config


def get_nginx_ssl_config(
    server_cert: str,
    server_key: str,
    ca_chain: str,
) -> str:
    """Generate Nginx SSL configuration."""
    return f'''
server {{
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate {server_cert};
    ssl_certificate_key {server_key};

    # Full chain including intermediate + root
    # ssl_trusted_certificate {ca_chain};

    # Modern TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Strong ciphers
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    location / {{
        root /var/www/html;
        index index.html;
    }}
}}
'''


def get_apache_ssl_config(
    server_cert: str,
    server_key: str,
    ca_chain: str,
) -> str:
    """Generate Apache SSL configuration."""
    return f'''
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile {server_cert}
    SSLCertificateKeyFile {server_key}
    SSLCertificateChainFile {ca_chain}

    # TLS 1.2 + 1.3 only
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1

    # Strong ciphers
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off

    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000"
</VirtualHost>
'''


def get_step_by_step_guide() -> str:
    """Get step-by-step PKI creation guide."""
    return """
3-Tier PKI Step-by-Step Guide
==============================

STEP 1: Create Directory Structure
----------------------------------
mkdir -p pki/root/{private,certs}
mkdir -p pki/intermediate/{private,certs,csr}

STEP 2: Create Root CA (OFFLINE)
--------------------------------
# Generate root CA key
openssl genrsa -out pki/root/private/ca.key.pem 4096

# Create self-signed root CA certificate
openssl req -config openssl.cnf -key pki/root/private/ca.key.pem \\
    -new -x509 -days 7300 -sha256 -extensions v3_ca \\
    -out pki/root/certs/ca.cert.pem \\
    -subj "/CN=Root CA/O=Custom PKI/C=US"

STEP 3: Create Intermediate CA
-------------------------------
# Generate intermediate key
openssl genrsa -out pki/intermediate/private/intermediate.key.pem 4096

# Create CSR
openssl req -config openssl.cnf -new -sha256 \\
    -key pki/intermediate/private/intermediate.key.pem \\
    -out pki/intermediate/csr/intermediate.csr.pem \\
    -subj "/CN=Intermediate CA/O=Custom PKI/C=US"

# Sign with Root CA
openssl ca -config openssl.cnf -extensions intermediate_ca \\
    -days 3650 -notext \\
    -in pki/intermediate/csr/intermediate.csr.pem \\
    -out pki/intermediate/certs/intermediate.cert.pem

# Create chain file (intermediate + root)
cat pki/intermediate/certs/intermediate.cert.pem pki/root/certs/ca.cert.pem \\
    > pki/intermediate/certs/ca-chain.cert.pem

STEP 4: Create Leaf Certificate
-------------------------------
# Generate server key
openssl genrsa -out server.key.pem 2048

# Create CSR with SAN
openssl req -new -key server.key.pem -out server.csr.pem \\
    -subj "/CN=example.com" \\
    -addext "subjectAltName=DNS:example.com,DNS:www.example.com"

# Sign with Intermediate CA
openssl ca -config openssl.cnf -extensions server_ext \\
    -days 365 -notext \\
    -in server.csr.pem -out server.cert.pem

# Verify
openssl verify -CAfile pki/intermediate/certs/ca-chain.cert.pem server.cert.pem

STEP 5: Deploy on Nginx
------------------------
# Copy certs to nginx directory
cp server.crt /etc/nginx/ssl/server.crt
cp server.key.pem /etc/nginx/ssl/server.key
cp pki/intermediate/certs/ca-chain.cert.pem /etc/nginx/ssl/ca-chain.crt

# Reload nginx
nginx -s reload
"""