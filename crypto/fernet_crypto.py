"""Fernet encryption helpers for Stage B.

Fernet is a symmetric encryption system from the cryptography library. Symmetric
means the same key is used for encryption and decryption.
"""

import json
import os
from typing import Any, Dict

from cryptography.fernet import Fernet

# Load keys from environment variables
# Keys should be set in .env file (local development) or environment (production)
IOT_TO_FOG_KEY = os.getenv("IOT_TO_FOG_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=").encode() if isinstance(os.getenv("IOT_TO_FOG_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="), str) else os.getenv("IOT_TO_FOG_KEY", b"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

FOG_TO_CLOUD_KEY = os.getenv("FOG_TO_CLOUD_KEY", "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=").encode() if isinstance(os.getenv("FOG_TO_CLOUD_KEY", "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA="), str) else os.getenv("FOG_TO_CLOUD_KEY", b"ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=")


def encrypt_message(message: Dict[str, Any], key: bytes) -> str:
    """Encrypt a Python dictionary and return a string token."""

    # Convert the Python dictionary to JSON bytes before encryption.
    plaintext = json.dumps(message).encode("utf-8")

    # Create a Fernet object using the fixed key for this communication hop.
    fernet = Fernet(key)

    # Fernet returns encrypted bytes, so decode them for JSON transport.
    encrypted_token = fernet.encrypt(plaintext)
    return encrypted_token.decode("utf-8")


def decrypt_message(encrypted_token: str, key: bytes) -> Dict[str, Any]:
    """Decrypt a string token and return the original Python dictionary."""

    # Create a Fernet object using the fixed key for this communication hop.
    fernet = Fernet(key)

    # Convert the token string back to bytes before decryption.
    plaintext = fernet.decrypt(encrypted_token.encode("utf-8"))

    # Convert the decrypted JSON bytes back into a Python dictionary.
    return json.loads(plaintext.decode("utf-8"))
