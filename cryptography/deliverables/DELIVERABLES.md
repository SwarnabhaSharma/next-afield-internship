# Cryptography Project - Deliverables Summary

## Project Location
`D:\Resume\NextAfield Internship\Cryptography`

---

## Deliverable 1: AES-256-GCM File Encryption/Decryption Tool

**Location:** `src/aes_gcm/`

**Features:**
- AES-256-GCM authenticated encryption (confidentiality + integrity + authenticity)
- 96-bit random nonce per encryption
- Argon2id key derivation from password
- CLI: `aes-gcm encrypt -i file.txt -o file.enc -p "password"`

**Run:**
```bash
cd "D:\Resume\NextAfield Internship\Cryptography"
python -m aes_gcm.cli encrypt -i secrets.txt -o secrets.enc -p "password"
python -m aes_gcm.cli decrypt -i secrets.enc -o decrypted.txt -p "password"
```

---

## Deliverable 2: RSA + ECDSA Signing and Verification

**Location:** `src/asymmetric/`

**Features:**
- RSA-4096 key generation, sign, verify
- ECDSA P-256 key generation, sign, verify
- ECDH key exchange demonstration
- X.509 certificate parsing

**Run:**
```bash
# Generate keys
python -m asymmetric.cli keygen ecdsa -o mykey

# Sign file
python -m asymmetric.cli sign ecdsa -i doc.txt -k mykey.private.pem -o doc.sig

# Verify
python -m asymmetric.cli verify ecdsa -i doc.txt -s doc.sig -k mykey.public.pem

# Parse certificate
python -m asymmetric.cli certinfo -c certificate.pem
```

---

## Deliverable 3: TLS 1.3 Handshake Analysis

**Location:** `src/tls/`

**Features:**
- TLS handshake analyzer (shows version, cipher, PFS status)
- SSLKEYLOGFILE capture instructions for Wireshark
- Perfect Forward Secrecy demonstration
- TLS configuration audit tool

**Run:**
```bash
# Analyze TLS handshake
python -m tls.cli handshake -h example.com

# Audit server TLS config
python -m tls.cli audit -h google.com

# Show capture instructions
python -m tls.cli capture
```

**Wireshark Setup:**
1. Set environment: `export SSLKEYLOGFILE=/tmp/ssl-keys.log`
2. Visit HTTPS site (or use curl)
3. In Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename

---

## Deliverable 4: 3-tier PKI with OpenSSL

**Location:** `src/pki/`

**Features:**
- Step-by-step guide for creating Root CA → Intermediate CA → Leaf
- Certificate extensions (basicConstraints, keyUsage, SAN, etc.)
- Nginx/Apache SSL config templates
- Certificate chain verification

**Run:**
```bash
# Show guide
python -m pki.cli guide

# Show extensions explanation
python -m pki.cli extensions

# Generate server config
python -m pki.cli config -s nginx -c server.crt -k server.key -b ca-chain.crt
```

**Manual Commands (require OpenSSL):**
```bash
# Root CA
openssl genrsa -out root.key.pem 4096
openssl req -x509 -new -nodes -key root.key.pem -sha256 -days 7300 -out root-ca.crt

# Intermediate
openssl genrsa -out intermediate.key.pem 4096
openssl req -new -key intermediate.key.pem -out intermediate.csr.pem
openssl x509 -req -in intermediate.csr.pem -CA root-ca.crt -CAkey root.key.pem -CAcreateserial -out intermediate.crt

# Leaf server cert
openssl genrsa -out server.key.pem 2048
openssl req -new -key server.key.pem -out server.csr.pem
openssl x509 -req -in server.csr.pem -CA intermediate.crt -CAkey intermediate.key.pem -CAcreateserial -out server.crt

# Verify
openssl verify -CAfile root-ca.crt -untrusted intermediate.crt server.crt
```

---

## Deliverable 5: HashiCorp Vault Demo

**Location:** `src/vault/`

**Features:**
- Transit engine (encryption as service)
- PKI secrets engine (automated cert issuance)
- Dynamic secrets (short-lived DB credentials)
- AppRole authentication
- Audit log integration

**Run:**
```bash
# Show concepts
python -m vault.cli concepts

# Transit demo
python -m vault.cli transit demo

# PKI demo
python -m vault.cli pki demo

# Dynamic secrets demo
python -m vault.cli dynamic demo

# AppRole demo
python -m vault.cli approle demo
```

**Note:** Requires Vault server running. Mocks provided for testing without server.

---

## Deliverable 6: Cryptographic Mistake Scanner

**Location:** `src/scanner/`

**Detected Patterns (6):**
1. CWE-328: Weak hash (MD5/SHA1 for passwords)
2. CWE-327: Weak crypto (ECB mode)
3. CWE-338: Weak PRNG (random.random for tokens)
4. CWE-798: Hardcoded credentials/keys
5. CWE-347: JWT algorithm 'none'
6. CWE-502: Insecure deserialization (pickle)

**Run:**
```bash
# Scan file
python -m scanner.cli scan-file app.py

# Scan directory
python -m scanner.cli scan-dir ./src

# Demo on sample vulnerable code
python -m scanner.cli demo

# List CWE patterns
python -m scanner.cli cwe-list
```

---

## Deliverable 7: testssl.sh Hardening Report

**Location:** `src/tls/config.py`

**Features:**
- TLS configuration audit tool (similar to testssl.sh concepts)
- Strong cipher recommendations
- Nginx/Apache config templates for A rating

**Run:**
```bash
# Audit server
python -m tls.cli audit -h yourserver.com

# Get strong config
python -m tls.cli strong
python -m tls.cli config -s nginx
```

---

## Deliverable 8: Secure vs Insecure Crypto Comparison Guide

**Location:** `src/` (each module includes documentation)

**Key Points:**

| Insecure | Secure | Why |
|----------|--------|-----|
| `hashlib.md5(password)` | `argon2-cffi` | MD5 is broken for passwords |
| `random.random()` | `secrets.token_urlsafe()` | Mersenne Twister is predictable |
| `AES.new(key, MODE_ECB)` | `AESGCM(key)` | ECB reveals patterns |
| Hardcoded keys | Environment variables / Vault | Exposed in source control |
| JWT algorithm "none" | Explicit algorithm list | Allows token forgery |
| `pickle.loads(untrusted)` | `json.loads()` | Pickle can execute code |
| `verify_mode=CERT_NONE` | Default context | Allows MITM attacks |

---

## Running Tests

```bash
cd "D:\Resume\NextAfield Internship\Cryptography"
python -m pytest tests/ -v
```

**Result: 109 tests passing**

---

## Project Structure

```
Cryptography/
├── src/
│   ├── aes_gcm/        # Step 1: AES-256-GCM encryption
│   ├── asymmetric/     # Step 2: RSA, ECDSA, ECDH, X.509
│   ├── tls/            # Step 3: TLS handshake analysis
│   ├── pki/            # Step 4: 3-tier PKI with OpenSSL
│   ├── vault/          # Step 5: HashiCorp Vault
│   └── scanner/        # Step 6: Crypto mistake scanner
├── tests/              # 109 tests
├── pyproject.toml
└── README.md
```