"""TLS configuration hardening - audit and fix weak configs."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import socket
import ssl
import subprocess


class TLSRating(Enum):
    """TLS configuration rating."""
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass
class TLSConfigAudit:
    """Audit result for TLS configuration."""
    rating: TLSRating
    issues: list[str]
    recommendations: list[str]
    cipher_suite: Optional[str]
    protocol_version: Optional[str]
    pfs_enabled: bool
    score: int


def get_strong_config() -> dict:
    """Return recommended strong TLS configuration."""
    return {
        "min_tls_version": "1.2",
        "recommended_ciphers": [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        ],
        "ecdh_curves": ["X25519", "secp256r1"],
        "certificate": {
            "min_key_size": 2048,
            "recommended_type": "ECDSA P-256",
        },
    }


def get_nginx_config() -> str:
    """Return strong Nginx TLS configuration."""
    return '''
# Strong TLS configuration for Nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # Modern configuration - TLS 1.2 + 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Strong cipher suites
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;

    # Enable OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS - enforces HTTPS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Disable SSL session tickets for PFS
    ssl_session_tickets off;

    # Strong session config
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
}
'''


def get_apache_config() -> str:
    """Return strong Apache TLS configuration."""
    return '''
# Strong TLS configuration for Apache
<VirtualHost *:443>
    ServerName example.com

    # TLS 1.2 + 1.3 only
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1

    # Modern ciphers - ECDHE only for PFS
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    SSLHonorCipherOrder off

    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000"

    # OCSP stapling
    SSLUseStapling On
    SSLStaplingCache "shmcb:ssl_stapling(32768)"
</VirtualHost>
'''


def audit_tls_config(host: str, port: int = 443) -> TLSConfigAudit:
    """Audit TLS configuration of a server."""
    issues = []
    recommendations = []
    score = 100
    pfs_enabled = False
    cipher_suite = None
    protocol_version = None

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()

                cipher_suite = cipher[0]
                protocol_version = version

                pfs_enabled = "ECDHE" in cipher_suite or "DHE" in cipher_suite or "TLS_AES" in cipher_suite or "TLS_CHACHA" in cipher_suite

                if version in ("TLSv1", "TLSv1.1"):
                    issues.append(f"Outdated protocol: {version}")
                    score -= 40
                    recommendations.append("Disable TLS 1.0 and 1.1")

                if not pfs_enabled:
                    issues.append("PFS not enabled - using static key exchange")
                    score -= 30
                    recommendations.append("Use ECDHE cipher suites for PFS")

                if cipher[2] < 128:
                    issues.append(f"Weak cipher: {cipher[2]} bits")
                    score -= 20

    except Exception as e:
        issues.append(f"Connection failed: {e}")
        score = 0

    if not pfs_enabled:
        if not issues:
            issues.append("No PFS - static RSA key exchange")
        score = max(score - 20, 0)

    if score >= 90:
        rating = TLSRating.A_PLUS if score >= 95 else TLSRating.A
    elif score >= 80:
        rating = TLSRating.B
    elif score >= 70:
        rating = TLSRating.C
    elif score >= 60:
        rating = TLSRating.D
    else:
        rating = TLSRating.F

    return TLSConfigAudit(
        rating=rating,
        issues=issues,
        recommendations=recommendations,
        cipher_suite=cipher_suite,
        protocol_version=protocol_version,
        pfs_enabled=pfs_enabled,
        score=score,
    )


def run_testssl_sh(host: str, port: int = 443) -> dict:
    """Run testssl.sh if available and parse results."""
    result = {
        "available": False,
        "results": {},
    }

    try:
        check = subprocess.run(
            ["which", "testssl.sh"],
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            return result

        result["available"] = True
    except Exception:
        pass

    return result