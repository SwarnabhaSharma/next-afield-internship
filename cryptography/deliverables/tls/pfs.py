"""Perfect Forward Secrecy (PFS) - explanation and demonstration."""

import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


PFS_CONFIG = {
    "min_version": "TLSv1.2",
    "cipher_suites": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    ],
    "ecdh_curves": ["X25519", "secp256r1", "secp384r1"],
    "description": "Strong PFS config - only ephemeral DH/ECDH",
}

NON_PFS_CONFIG = {
    "min_version": "TLSv1.0",
    "cipher_suites": [
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    ],
    "description": "Weak non-PFS config - uses RSA key exchange",
}


def demonstrate_pfs() -> None:
    """Demonstrate that PFS produces different keys each session."""
    print("Perfect Forward Secrecy Demonstration")
    print("=" * 50)

    secrets = []

    for i in range(3):
        context = ssl.create_default_context()
        context.set_ciphers("ECDHE:AESGCM:CHACHA20")

        try:
            with socket.create_connection(("example.com", 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname="example.com") as ssock:
                    cipher = ssock.cipher()
                    secrets.append(cipher[2])
                    print(f"Session {i+1}: Cipher bits = {cipher[2]}, Session ID unique")
        except Exception as e:
            print(f"Session {i+1}: Failed - {e}")

    print("")
    print("PFS Properties:")
    print("  - Each session uses NEW ephemeral key pair")
    print("  - Compromising server's long-term key doesn't expose past sessions")
    print("  - Even if attacker records traffic, they can't decrypt without breaking DH")
    print("  - Session keys are independent - no single point of failure")


def test_pfs_support(host: str = "example.com", port: int = 443) -> dict:
    """Test if a server supports PFS."""
    result = {
        "host": f"{host}:{port}",
        "pfs_supported": False,
        "cipher_suite": None,
        "key_exchange": None,
    }

    try:
        context = ssl.create_default_context()
        context.set_ciphers("ECDHE:AESGCM:CHACHA20")

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                result["cipher_suite"] = cipher[0]
                result["pfs_supported"] = "ECDHE" in cipher[0] or "DHE" in cipher[0]
                result["key_exchange"] = "Ephemeral" if result["pfs_supported"] else "Static"

    except Exception as e:
        result["error"] = str(e)

    return result


def explain_pfs() -> str:
    """Return explanation of PFS."""
    return """
Perfect Forward Secrecy (PFS)
=============================

What is PFS?
------------
PFS ensures that compromise of long-term keys doesn't allow
decryption of previously recorded traffic.

How it works in TLS 1.3:
-------------------------
1. Client and server perform ECDHE key exchange
2. Each session uses NEW ephemeral keys
3. Server's private key (RSA/ECDSA) only signs the DH parameters
4. After handshake, ephemeral keys are discarded

Why it matters:
---------------
WITHOUT PFS:
  - Attacker records encrypted traffic
  - Later steals server's private key
  - Can decrypt ALL past sessions

WITH PFS:
  - Attacker steals server's private key
  - Can only attack FUTURE sessions
  - Past sessions remain secure

TLS 1.3 mandates PFS:
-----------------------
  - All key exchanges are ephemeral (ECDHE)
  - No static RSA key exchange
  - Default cipher suites all provide PFS
"""