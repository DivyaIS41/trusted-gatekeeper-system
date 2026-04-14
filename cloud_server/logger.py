"""Audit logging helpers for the Cloud Server."""

from datetime import datetime
from pathlib import Path


# Cloud audit logs include accepted data and blocked-message reports from Fog.
LOG_FILE = Path("logs") / "cloud_audit.log"


def reset_cloud_log() -> None:
    """Clear the Cloud audit log when the Cloud Server starts."""

    LOG_FILE.parent.mkdir(exist_ok=True)
    LOG_FILE.write_text("", encoding="utf-8")
    print(f"[Cloud][Audit] Reset log file: {LOG_FILE}")


def log_cloud_event(event_type: str, reason: str, message: dict) -> None:
    """Write one Cloud audit event to the console and the log file."""

    # Create the logs folder the first time the Cloud writes an audit event.
    LOG_FILE.parent.mkdir(exist_ok=True)

    # Use UTC to make Cloud and Fog logs easy to compare.
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # A simple pipe-separated line is beginner-friendly and easy to scan.
    log_line = (
        f"{timestamp} | event={event_type} | reason={reason} | "
        f"message={message}"
    )

    print(f"[Cloud][Audit] {log_line}")

    # Append so the audit trail grows during a run.
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(log_line + "\n")
