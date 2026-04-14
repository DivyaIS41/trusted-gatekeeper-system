"""Launcher for the Streamlit dashboard.

Run with:
    python run_dashboard.py

This wrapper gives a clearer error message when Streamlit is not installed.
"""

import subprocess
import sys
from importlib.util import find_spec


def main() -> None:
    """Start the Streamlit dashboard using the current Python interpreter."""

    if find_spec("streamlit") is None:
        print("Streamlit is not installed for this Python interpreter.")
        print("Install dependencies with: python -m pip install -r requirements.txt")
        return

    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "dashboard/app.py",
    ]

    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as error:
        print(f"Dashboard failed to start. Exit code: {error.returncode}")


if __name__ == "__main__":
    main()
