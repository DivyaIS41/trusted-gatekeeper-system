"""Zero-Trust and attack-detection checks for the Fog Gateway."""

import time
from typing import Any, Dict, List, Tuple


# Only devices in this set are allowed to send data through the Fog Gateway.
TRUSTED_DEVICE_IDS = {
    "iot-device-001",
}

# Messages older than this many seconds are rejected.
MAX_MESSAGE_AGE_SECONDS = 30

# At most this many messages are accepted from one device inside the time window.
MAX_MESSAGES_PER_WINDOW = 5

# The flooding detection window size in seconds.
RATE_LIMIT_WINDOW_SECONDS = 10

# The Fog stores seen nonces in memory so the same message cannot be replayed.
# The key is a tuple of (device_id, nonce).
USED_NONCES = set()

# The Fog stores recent message arrival times per device for flooding detection.
DEVICE_MESSAGE_TIMESTAMPS: Dict[str, List[int]] = {}


def reset_security_state() -> None:
    """Clear in-memory nonce and rate-limit state when the Fog Gateway starts."""

    USED_NONCES.clear()
    DEVICE_MESSAGE_TIMESTAMPS.clear()


def validate_message(message: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Validate one decrypted IoT message using Zero-Trust and attack rules."""

    # Every message must explicitly identify the device and freshness values.
    required_fields = {"device_id", "timestamp", "nonce", "payload"}
    missing_fields = required_fields - message.keys()
    if missing_fields:
        return False, f"Missing required fields: {sorted(missing_fields)}", "malformed_message"

    # Reject unknown devices immediately.
    device_id = message["device_id"]
    if device_id not in TRUSTED_DEVICE_IDS:
        return False, f"Unknown device ID: {device_id}", "fake_device_attack"

    # Validate that the timestamp is a number.
    try:
        message_timestamp = int(message["timestamp"])
    except (TypeError, ValueError):
        return False, "Timestamp must be a Unix timestamp integer.", "malformed_message"

    current_timestamp = int(time.time())
    message_age = current_timestamp - message_timestamp

    # Reject old messages because they may be replayed by an attacker.
    if message_age > MAX_MESSAGE_AGE_SECONDS:
        return False, "Message timestamp is too old.", "replay_attack"

    # Reject timestamps that are far in the future because they are suspicious.
    if message_age < -MAX_MESSAGE_AGE_SECONDS:
        return False, "Message timestamp is too far in the future.", "suspicious_timestamp"

    # Reject a device that sends too many messages too quickly.
    if is_flooding(device_id, current_timestamp):
        return False, "Flooding detected: too many messages in a short time.", "flooding_attack"

    # A nonce is a one-time random value. Reusing it means the message may be a replay.
    nonce = message["nonce"]
    nonce_key = (device_id, nonce)
    if nonce_key in USED_NONCES:
        return False, "Nonce was already used.", "replay_attack"

    # Store the nonce only after all checks pass.
    USED_NONCES.add(nonce_key)

    # Store this accepted message time for future flooding decisions.
    DEVICE_MESSAGE_TIMESTAMPS.setdefault(device_id, []).append(current_timestamp)
    return True, "Message passed Zero-Trust checks.", "allowed"


def is_flooding(device_id: str, current_timestamp: int) -> bool:
    """Return True when one trusted device is sending too many messages."""

    # Load this device's recent accepted message times.
    recent_timestamps = DEVICE_MESSAGE_TIMESTAMPS.setdefault(device_id, [])

    # Keep only timestamps inside the rate-limit window.
    window_start = current_timestamp - RATE_LIMIT_WINDOW_SECONDS
    recent_timestamps[:] = [
        timestamp for timestamp in recent_timestamps if timestamp >= window_start
    ]

    # If the window already has the maximum allowed messages, block this one.
    return len(recent_timestamps) >= MAX_MESSAGES_PER_WINDOW
