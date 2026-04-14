"""Fog Gateway for Zero-Trust communication and attack blocking.

The Fog Gateway is the security checkpoint between IoT devices and the Cloud.
It decrypts IoT messages, verifies device ID, timestamp, nonce, and rate, then
re-encrypts accepted messages before forwarding to the Cloud Server.
"""

import socket

from cryptography.fernet import InvalidToken

from common.network import receive_json, send_json
from common.settings import CLOUD_PORT, FOG_PORT, HOST
from crypto.fernet_crypto import (
    FOG_TO_CLOUD_KEY,
    IOT_TO_FOG_KEY,
    decrypt_message,
    encrypt_message,
)
from fog_gateway.logger import log_debug_event, log_security_event, reset_security_log
from fog_gateway.security import reset_security_state, validate_message


def forward_to_cloud(message: dict) -> dict:
    """Encrypt and forward one IoT message to the Cloud Server."""

    # Open a new TCP connection from Fog to Cloud.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cloud_socket:
        cloud_socket.connect((HOST, CLOUD_PORT))

        # Wrap the IoT data so the Cloud can see that Fog forwarded it.
        forwarded_message = {
            "forwarded_by": "fog_gateway",
            "original_message": message,
        }

        # Re-encrypt the plaintext message using the Fog-to-Cloud key.
        encrypted_payload = encrypt_message(forwarded_message, FOG_TO_CLOUD_KEY)
        encrypted_message = {
            "sender": "fog_gateway",
            "receiver": "cloud_server",
            "encryption": "fernet",
            "encrypted_payload": encrypted_payload,
        }

        # Send the encrypted message and wait for the Cloud acknowledgement.
        print(f"[Fog] Forwarding encrypted message to Cloud: {encrypted_message}")
        send_json(cloud_socket, encrypted_message)
        return receive_json(cloud_socket)


def report_blocked_message_to_cloud(
    blocked_event_type: str,
    reason: str,
    blocked_message: dict,
) -> None:
    """Send only a blocked-message audit report to Cloud."""

    # This does not forward the blocked message as sensor data. It lets Cloud
    # record why Fog blocked the traffic.
    audit_message = {
        "forwarded_by": "fog_gateway",
        "event_type": "blocked_message",
        "reason": reason,
        "blocked_event_type": blocked_event_type,
        "blocked_message": blocked_message,
    }

    try:
        cloud_response = forward_audit_message_to_cloud(audit_message)
        print(f"[Fog] Cloud logged blocked-message report: {cloud_response}")
    except OSError as error:
        print(f"[Fog] Could not report blocked message to Cloud: {error}")


def forward_audit_message_to_cloud(audit_message: dict) -> dict:
    """Encrypt and send one audit-only message from Fog to Cloud."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cloud_socket:
        cloud_socket.connect((HOST, CLOUD_PORT))

        encrypted_payload = encrypt_message(audit_message, FOG_TO_CLOUD_KEY)
        encrypted_message = {
            "sender": "fog_gateway",
            "receiver": "cloud_server",
            "encryption": "fernet",
            "encrypted_payload": encrypted_payload,
        }

        send_json(cloud_socket, encrypted_message)
        return receive_json(cloud_socket)


def handle_iot_device(device_socket: socket.socket, device_address: tuple) -> None:
    """Receive IoT messages, verify each one, and forward only trusted data."""

    print(f"[Fog] Connection accepted from IoT device {device_address}")

    # Keep this IoT connection open for periodic messages.
    while True:
        # Receive one encrypted message from the IoT device.
        try:
            encrypted_message = receive_json(device_socket)
        except ConnectionError:
            print(f"[Fog] IoT device disconnected: {device_address}")
            break

        print(f"[Fog] Encrypted message received: {encrypted_message}")

        # Decrypt the IoT message using the IoT-to-Fog key.
        try:
            message = decrypt_message(
                encrypted_message["encrypted_payload"],
                IOT_TO_FOG_KEY,
            )
        except (InvalidToken, KeyError) as error:
            reason = f"Could not decrypt IoT message: {error}"
            response = {
                "status": "rejected",
                "receiver": "fog",
                "details": reason,
            }
            send_json(device_socket, response)
            print(f"[Fog] Rejected encrypted message: {response}")
            log_debug_event("invalid_encrypted_message", reason, encrypted_message)
            log_security_event("invalid_encrypted_message", reason, encrypted_message)
            report_blocked_message_to_cloud(
                "invalid_encrypted_message",
                reason,
                encrypted_message,
            )
            continue

        print(f"[Fog] Decrypted IoT message: {message}")

        # Apply Zero-Trust and attack-detection checks before forwarding anything.
        is_allowed, decision_reason, event_type = validate_message(message)
        log_debug_event(event_type, decision_reason, message)
        if not is_allowed:
            response = {
                "status": "rejected",
                "receiver": "fog",
                "details": decision_reason,
                "event_type": event_type,
            }
            send_json(device_socket, response)
            print(f"[Fog] Message rejected: {decision_reason}")
            log_security_event(event_type, decision_reason, message)
            report_blocked_message_to_cloud(event_type, decision_reason, message)
            continue

        print(f"[Fog] Message accepted: {decision_reason}")

        # Accepted messages are re-encrypted before forwarding to Cloud.
        cloud_response = forward_to_cloud(message)
        print(f"[Fog] Cloud response: {cloud_response}")

        # Return a simple acknowledgement to the IoT device.
        response = {
            "status": "forwarded",
            "receiver": "fog",
            "details": "Message passed Zero-Trust checks and was forwarded.",
            "cloud_response": cloud_response,
        }
        send_json(device_socket, response)


def start_fog_gateway() -> None:
    """Start the Fog Gateway and wait for IoT device connections."""

    # Start each Fog run with fresh runtime logs and fresh replay/rate-limit memory.
    reset_security_log()
    reset_security_state()

    # AF_INET means IPv4, and SOCK_STREAM means TCP.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Allow the port to be reused quickly after restarting the script.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the Fog Gateway to localhost and the configured fog port.
        server_socket.bind((HOST, FOG_PORT))

        # Start listening for IoT device connections.
        server_socket.listen()
        print(f"[Fog] Listening on {HOST}:{FOG_PORT}")

        # Keep the gateway alive for repeated IoT messages.
        while True:
            device_socket, device_address = server_socket.accept()

            # The context manager closes this IoT connection after handling it.
            with device_socket:
                try:
                    handle_iot_device(device_socket, device_address)
                except ConnectionError as error:
                    print(f"[Fog] Connection error: {error}")


if __name__ == "__main__":
    start_fog_gateway()
