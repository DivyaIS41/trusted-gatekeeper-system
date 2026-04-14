"""Security logging helpers for the Fog Gateway."""

from datetime import datetime
from pathlib import Path


# Store logs in a local folder so attack evidence is easy to find after a run.
LOG_FILE = Path("logs") / "fog_security.log"


def reset_security_log() -> None:
    """Clear the Fog security log when the Fog Gateway starts."""

    LOG_FILE.parent.mkdir(exist_ok=True)
    LOG_FILE.write_text("", encoding="utf-8")
    print(f"[Fog][Security] Reset log file: {LOG_FILE}")


def log_debug_event(rule_name: str, reason: str, message: dict) -> None:
    """Print a beginner-friendly validation debug message."""

    device_id = message.get("device_id", "unknown")
    print(
        f"[Fog][Debug] rule={rule_name} | device={device_id} | "
        f"reason={reason}"
    )


def log_security_event(event_type: str, reason: str, message: dict) -> None:
    """Write one Fog security event to the console and the log file."""

    # Create the logs folder the first time the Fog needs to write an event.
    LOG_FILE.parent.mkdir(exist_ok=True)

    # Use UTC so log times are consistent across machines.
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # Keep the log line simple so beginners can read it without a log parser.
    log_line = (
        f"{timestamp} | event={event_type} | reason={reason} | "
        f"message={message}"
    )

    print(f"[Fog][Security] {log_line}")

    # Append instead of overwriting so multiple attack attempts are preserved.
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(log_line + "\n")
