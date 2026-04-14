"""Network settings for the IoT-Fog-Cloud communication system."""

import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# The demo runs locally on one machine, so every component binds to localhost.
HOST = os.getenv("HOST", "127.0.0.1")

# The Fog Gateway listens for IoT device messages on this port.
FOG_PORT = int(os.getenv("FOG_PORT", "5001"))

# The Cloud Server listens for forwarded Fog Gateway messages on this port.
CLOUD_PORT = int(os.getenv("CLOUD_PORT", "6001"))

# The IoT Device waits this many seconds between sensor messages.
IOT_SEND_INTERVAL_SECONDS = int(os.getenv("IOT_SEND_INTERVAL_SECONDS", "5"))
