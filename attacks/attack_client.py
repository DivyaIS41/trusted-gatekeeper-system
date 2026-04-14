"""Shared helpers for attack simulation clients."""

import socket
from typing import Any, Dict

from common.network import receive_json, send_json
from common.settings import FOG_PORT, HOST
from crypto.fernet_crypto import IOT_TO_FOG_KEY, encrypt_message


SOCKET_TIMEOUT_SECONDS = 5


def send_plaintext_as_encrypted_iot_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt one attack message and send it to the Fog Gateway."""

    # Attack scripts still use the real IoT-to-Fog encryption path.
    encrypted_payload = encrypt_message(message, IOT_TO_FOG_KEY)

    # This envelope matches the normal IoT message format used by the project.
    encrypted_message = {
        "sender": "iot_device",
        "receiver": "fog_gateway",
        "encryption": "fernet",
        "encrypted_payload": encrypted_payload,
    }

    # Open a short TCP connection, send one message, and return Fog's response.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # Prevent attack scripts from hanging forever when Fog is not ready.
            client_socket.settimeout(SOCKET_TIMEOUT_SECONDS)

            client_socket.connect((HOST, FOG_PORT))
            send_json(client_socket, encrypted_message)
            return receive_json(client_socket)

    except ConnectionRefusedError:
        return {
            "status": "error",
            "details": "Fog Gateway is not running on the expected port.",
            "fix": "Start it with: python -m fog_gateway.gateway",
        }

    except socket.timeout:
        return {
            "status": "error",
            "details": "Timed out waiting for Fog Gateway response.",
            "fix": "Make sure Fog is running and restart old stuck backend terminals.",
        }

    except OSError as error:
        return {
            "status": "error",
            "details": f"Socket error: {error}",
            "fix": "Start Cloud first, then Fog, then run one attack command.",
        }
