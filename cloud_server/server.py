"""Cloud Server for encrypted communication and accepted-message logging.

The Cloud Server receives encrypted data from the Fog Gateway, decrypts it, and
prints and logs the plaintext message.
"""

import socket

from common.network import receive_json, send_json
from common.settings import CLOUD_PORT, HOST
from crypto.fernet_crypto import FOG_TO_CLOUD_KEY, decrypt_message
from cloud_server.logger import log_cloud_event, reset_cloud_log


def start_cloud_server() -> None:
    """Start the Cloud Server and wait for forwarded Fog Gateway messages."""

    # Start each Cloud run with a fresh accepted-message audit log.
    reset_cloud_log()

    # AF_INET means IPv4, and SOCK_STREAM means TCP.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Allow the port to be reused quickly after restarting the script.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the server to localhost and the configured cloud port.
        server_socket.bind((HOST, CLOUD_PORT))

        # Start listening for incoming TCP connections.
        server_socket.listen()
        print(f"[Cloud] Listening on {HOST}:{CLOUD_PORT}")

        # Keep the server alive so it can receive multiple forwarded messages.
        while True:
            # accept() waits until the Fog Gateway connects.
            client_socket, client_address = server_socket.accept()

            # The context manager closes this connection after handling it.
            with client_socket:
                print(f"[Cloud] Connection accepted from {client_address}")

                # Read one encrypted JSON envelope sent by the Fog Gateway.
                encrypted_message = receive_json(client_socket)
                print(f"[Cloud] Encrypted message received: {encrypted_message}")

                # Decrypt the message using the Fog-to-Cloud key.
                message = decrypt_message(
                    encrypted_message["encrypted_payload"],
                    FOG_TO_CLOUD_KEY,
                )
                print(f"[Cloud] Decrypted data received: {message}")
                event_type = message.get("event_type", "accepted_message")
                reason = message.get(
                    "reason",
                    "Message accepted by Fog Gateway and received by Cloud.",
                )
                log_cloud_event(event_type, reason, message)

                # Send a simple acknowledgement back to the Fog Gateway.
                response = {
                    "status": "stored",
                    "receiver": "cloud",
                    "details": "Message received from Fog Gateway.",
                }
                send_json(client_socket, response)


if __name__ == "__main__":
    start_cloud_server()
