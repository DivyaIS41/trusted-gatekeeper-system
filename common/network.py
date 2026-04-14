"""Small TCP helper functions for the Trusted Gatekeeper System.

Stage A uses JSON messages over TCP. TCP is a stream protocol, which means one
recv() call is not guaranteed to return one full message. To solve that cleanly,
each JSON message is sent with a 4-byte length header before the message body.
"""

import json
import socket
from typing import Any, Dict


# The length header is always exactly 4 bytes.
HEADER_SIZE = 4


def send_json(sock: socket.socket, message: Dict[str, Any]) -> None:
    """Serialize a dictionary to JSON and send it through a TCP socket."""

    # Convert the Python dictionary into UTF-8 encoded JSON bytes.
    payload = json.dumps(message).encode("utf-8")

    # Store the payload length in exactly 4 bytes using network byte order.
    header = len(payload).to_bytes(HEADER_SIZE, byteorder="big")

    # sendall() keeps sending until the full header and payload are transmitted.
    sock.sendall(header + payload)


def receive_json(sock: socket.socket) -> Dict[str, Any]:
    """Read one length-prefixed JSON message from a TCP socket."""

    # First read the fixed-size header so we know how many bytes to expect.
    header = _receive_exactly(sock, HEADER_SIZE)
    payload_length = int.from_bytes(header, byteorder="big")

    # Then read exactly that many bytes for the JSON message body.
    payload = _receive_exactly(sock, payload_length)

    # Convert JSON bytes back into a Python dictionary.
    return json.loads(payload.decode("utf-8"))


def _receive_exactly(sock: socket.socket, number_of_bytes: int) -> bytes:
    """Keep reading from the socket until the requested byte count is reached."""

    # A bytearray is efficient for gradually building a bytes value.
    data = bytearray()

    # Continue until the buffer contains the full requested message part.
    while len(data) < number_of_bytes:
        chunk = sock.recv(number_of_bytes - len(data))

        # An empty chunk means the peer closed the connection unexpectedly.
        if not chunk:
            raise ConnectionError("TCP connection closed before full message arrived.")

        data.extend(chunk)

    return bytes(data)

