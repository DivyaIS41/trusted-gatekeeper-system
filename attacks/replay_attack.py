"""Simulate a replay attack.

A replay attack sends the same valid-looking message twice. The first message
may pass, but the second must be rejected because it reuses the same nonce.
"""

import secrets
import time

from attacks.attack_client import send_plaintext_as_encrypted_iot_message


def run_attack() -> None:
    """Send the same trusted-device message twice."""

    # This message uses a trusted device ID but a nonce that will be reused.
    replayed_message = {
        "device_id": "iot-device-001",
        "message_type": "sensor_reading",
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(16),
        "payload": {
            "temperature_celsius": 31.2,
            "humidity_percent": 70,
        },
    }

    print(f"[Attack: Replay] First send: {replayed_message}")
    first_response = send_plaintext_as_encrypted_iot_message(replayed_message)
    print(f"[Attack: Replay] First Fog response: {first_response}")

    print("[Attack: Replay] Sending the exact same message again.")
    second_response = send_plaintext_as_encrypted_iot_message(replayed_message)
    print(f"[Attack: Replay] Second Fog response: {second_response}")


if __name__ == "__main__":
    run_attack()
