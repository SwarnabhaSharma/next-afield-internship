"""SSLKEYLOGFILE capture setup for decrypting TLS traffic in Wireshark."""

import os
import sys
from dataclasses import dataclass
from typing import Optional
import subprocess


@dataclass
class KeylogCapture:
    """Manages SSL key log capture."""
    log_file: str

    def __post_init__(self):
        self._original_env = os.environ.get("SSLKEYLOGFILE")

    def __enter__(self):
        os.environ["SSLKEYLOGFILE"] = self.log_file
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._original_env is None:
            os.environ.pop("SSLKEYLOGFILE", None)
        else:
            os.environ["SSLKEYLOGFILE"] = self._original_env


def setup_keylog_capture(log_file: str = "ssl-keys.log") -> KeylogCapture:
    """Create context manager for SSL key logging.

    Usage:
        with setup_keylog_capture("keys.log") as capture:
            # Launch browser or curl
            subprocess.run(["curl", "https://example.com"])
        # keys.log now containspre-master secrets
    """
    return KeylogCapture(log_file)


def get_instructions() -> str:
    """Return instructions for capturing TLS keys."""
    return """
SSLKEYLOGFILE Capture Setup
============================

This allows Wireshark to decrypt TLS traffic for analysis.

METHOD 1: Environment Variable (for any program)
-------------------------------------------------
    export SSLKEYLOGFILE=/tmp/ssl-keys.log
    # Now run your browser or curl
    curl https://example.com

METHOD 2: Firefox
-----------------
    1. Enter: about:config
    2. Set: security.ssl_keylog_file = /tmp/ssl-keys.log

METHOD 3: Chrome
-----------------
    chrome.exe --ssl-key-log-file=C:\\keys.log

Wireshark Setup
---------------
    1. Edit -> Preferences -> Protocols -> TLS
    2. (Pre)-Master-Secret log filename: /tmp/ssl-keys.log
    3. Reload capture file

SECURITY NOTE: This logs keys in plaintext. Delete after analysis!
"""


def parse_keylog_file(log_file: str) -> dict:
    """Parse SSLKEYLOGFILE to extract session keys."""
    keys = {}
    try:
        with open(log_file, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] in ("CLIENT_RANDOM", "SERVER_RANDOM"):
                    keys[parts[1]] = parts[2]
    except FileNotFoundError:
        pass
    return keys


def check_prerequisites() -> dict:
    """Check if capture prerequisites are available."""
    return {
        "wireshark_available": bool(subprocess.run(["which", "wireshark"], capture_output=True).returncode == 0),
        "tshark_available": bool(subprocess.run(["which", "tshark"], capture_output=True).returncode == 0),
        "tcpdump_available": bool(subprocess.run(["which", "tcpdump"], capture_output=True).returncode == 0),
    }