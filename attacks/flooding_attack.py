"""Simulate a flooding or DoS-style attack.

Flooding sends many messages quickly so the Fog Gateway rate limit is triggered.
"""

import secrets
import time

from attacks.attack_client import send_plaintext_as_encrypted_iot_message


def run_attack() -> None:
    """Send many trusted-device messages rapidly."""

    # Send more than the Fog's MAX_MESSAGES_PER_WINDOW limit.
    for message_number in range(1, 11):
        flood_message = {
            "device_id": "iot-device-001",
            "message_type": "sensor_reading",
            "timestamp": int(time.time()),
            "nonce": secrets.token_hex(16),
            "payload": {
                "temperature_celsius": 40 + message_number,
                "humidity_percent": 20,
            },
        }

        print(f"[Attack: Flooding] Sending message {message_number}")
        response = send_plaintext_as_encrypted_iot_message(flood_message)
        print(f"[Attack: Flooding] Fog response {message_number}: {response}")


if __name__ == "__main__":
    run_attack()
