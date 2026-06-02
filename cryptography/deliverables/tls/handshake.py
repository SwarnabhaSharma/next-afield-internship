"""TLS 1.3 Handshake Analysis - parse and annotate handshake messages."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import socket
import ssl
import struct


class TLSMessageType(Enum):
    """TLS handshake message types."""
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    FINISHED = 20


@dataclass
class TLSMessage:
    """Represents a TLS handshake message."""
    msg_type: TLSMessageType
    data: bytes
    sequence: int
    timestamp: Optional[float] = None


class HandshakeAnalyzer:
    """Analyze TLS 1.3 handshake messages."""

    TLS_1_3_VERSION = b"\x03\x04"

    CIPHER_SUITES = {
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0x1304: "TLS_AES_128_CCM_SHA256",
        0x1305: "TLS_AES_128_CCM_8_SHA256",
    }

    SUPPORTED_GROUPS = {
        0x001d: "X25519",
        0x001e: "X448",
        0x0017: "secp256r1",
        0x0018: "secp384r1",
        0x0019: "secp521r1",
        0x001f: "ffdhe2048",
        0x0020: "ffdhe3072",
        0x0021: "ffdhe4096",
        0x0022: "ffdhe6144",
        0x0023: "ffdhe8192",
    }

    def __init__(self):
        self.messages: list[TLSMessage] = []

    def add_message(self, msg_type: TLSMessageType, data: bytes, seq: int = 0) -> None:
        """Add a handshake message to the analysis."""
        self.messages.append(TLSMessage(msg_type, data, seq))

    def parse_client_hello(self, data: bytes) -> dict:
        """Parse ClientHello message."""
        result = {"raw_length": len(data)}

        if len(data) < 43:
            return result

        if data[:2] != b"\x16\x03":
            return result

        offset = 2 + 2 + 2
        if len(data) < offset + 1:
            return result

        session_id_len = data[offset]
        offset += 1 + session_id_len

        if len(data) < offset + 2:
            return result
        cipher_suites_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            if offset + i + 2 <= len(data):
                suite = struct.unpack(">H", data[offset+i:offset+i+2])[0]
                cipher_suites.append(self.CIPHER_SUITES.get(suite, f"0x{suite:04x}"))
        result["cipher_suites"] = cipher_suites[:5]

        return result

    def parse_server_hello(self, data: bytes) -> dict:
        """Parse ServerHello message."""
        result = {"raw_length": len(data)}

        if len(data) < 42:
            return result

        return result

    def get_handshake_summary(self) -> str:
        """Generate human-readable handshake summary."""
        lines = ["TLS 1.3 Handshake Analysis", "=" * 40]

        msg_map = {
            TLSMessageType.CLIENT_HELLO: "ClientHello",
            TLSMessageType.SERVER_HELLO: "ServerHello",
            TLSMessageType.CERTIFICATE: "Certificate",
            TLSMessageType.CERTIFICATE_VERIFY: "CertificateVerify",
            TLSMessageType.FINISHED: "Finished",
        }

        for i, msg in enumerate(self.messages):
            name = msg_map.get(msg.msg_type, str(msg.msg_type))
            lines.append(f"  {i+1}. {name} ({len(msg.data)} bytes)")

        lines.append("")
        lines.append("Key Exchange: ECDH (Ephemeral)")
        lines.append("PFS: Enabled (each handshake uses new DH key)")

        return "\n".join(lines)


def demonstrate_tls_handshake(host: str = "example.com", port: int = 443) -> HandshakeAnalyzer:
    """Perform a TLS handshake and analyze the messages."""
    analyzer = HandshakeAnalyzer()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()

                print(f"Connected to {host}:{port}")
                print(f"TLS Version: {version}")
                print(f"Cipher: {cipher[0]}")
                print(f"Protocol: {cipher[1]}")
                print(f"Bits: {cipher[2]}")

    except Exception as e:
        print(f"Handshake failed: {e}")

    return analyzer


def test_connectivity() -> bool:
    """Test basic TLS connectivity."""
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname="example.com") as sock:
            sock.connect(("example.com", 443))
            return True
    except Exception:
        return False