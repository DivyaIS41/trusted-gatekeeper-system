"""Simulate a fake device attack.

A fake device attack uses a device ID that the Fog Gateway does not trust.
"""

import secrets
import time

from attacks.attack_client import send_plaintext_as_encrypted_iot_message


def run_attack() -> None:
    """Send one encrypted message with an unknown device ID."""

    # The device ID is intentionally not in the Fog Gateway trusted list.
    fake_message = {
        "device_id": "iot-device-999",
        "message_type": "sensor_reading",
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(16),
        "payload": {
            "temperature_celsius": 99.9,
            "humidity_percent": 5,
        },
    }

    print(f"[Attack: Fake Device] Sending: {fake_message}")
    response = send_plaintext_as_encrypted_iot_message(fake_message)
    print(f"[Attack: Fake Device] Fog response: {response}")


if __name__ == "__main__":
    run_attack()
