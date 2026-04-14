"""Print a simple security summary from Fog and Cloud log files."""

from collections import Counter
from pathlib import Path


LOG_FILES = {
    "Fog security log": Path("logs") / "fog_security.log",
    "Cloud audit log": Path("logs") / "cloud_audit.log",
}


def extract_event_type(log_line: str) -> str:
    """Extract the event type from one pipe-separated log line."""

    # Log lines look like: timestamp | event=name | reason=text | message={...}
    for part in log_line.split("|"):
        clean_part = part.strip()
        if clean_part.startswith("event="):
            return clean_part.replace("event=", "", 1)

    return "unknown_event"


def print_summary_for_file(title: str, log_file: Path) -> None:
    """Print event counts for one log file."""

    print(f"\n{title}")
    print("-" * len(title))

    if not log_file.exists():
        print(f"No log file found at {log_file}")
        return

    # Read only non-empty lines so blank lines do not affect counts.
    log_lines = [
        line.strip()
        for line in log_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    if not log_lines:
        print("Log file exists, but it has no events yet.")
        return

    # Count event types to show what happened during the run.
    event_counts = Counter(extract_event_type(line) for line in log_lines)
    for event_type, count in event_counts.items():
        print(f"{event_type}: {count}")

    print(f"Total events: {len(log_lines)}")


def main() -> None:
    """Print a summary report for all known system logs."""

    print("Trusted Gatekeeper Security Summary")
    print("===================================")

    for title, log_file in LOG_FILES.items():
        print_summary_for_file(title, log_file)


if __name__ == "__main__":
    main()
