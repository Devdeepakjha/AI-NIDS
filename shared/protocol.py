"""
=============================================================================
shared/protocol.py  —  Network Message Protocol  (Phase 2)
=============================================================================

PROJECT : AI-Based Network Intrusion Detection System
PHASE   : 2 — Structured Network Protocol
IMPORTED BY: server/server.py  AND  client/client.py

PURPOSE
-------
This module is the single source of truth for everything related to the
message format exchanged between client and server.  It provides:

  1. Request/response builders    — build_request(), build_response()
  2. TCP framing                  — send_message(), recv_message()
  3. Validation                   — validate_request()
  4. Shared constants             — REQUEST_TYPES, REQUIRED_FIELDS

WHY A SHARED MODULE?
--------------------
Both the client and the server need to agree on the same message format.
Keeping that logic in one place ensures they can never drift out of sync.
Phases 3–8 will import this module without modification to the core protocol.

SIZE TERMINOLOGY — IMPORTANT
------------------------------
There are four distinct "sizes" in any real network transfer.
Phase 2 measures ONLY the first one:

  1. Application payload size    [THIS PHASE]
       len(payload.encode("utf-8")) — bytes of user-defined data
       Stored in the "payload_size" field of every request.

  2. TCP segment payload size    [Phase 3+]
       Application payload + any protocol overhead inside the TCP stream.
       Measured at the OS socket layer.

  3. IP packet size              [Phase 3+]
       TCP segment + TCP header (20 bytes) + IP header (20 bytes typical).
       Visible via raw sockets or packet capture.

  4. Total bytes on wire         [Phase 3+]
       IP packet + Ethernet frame header (14 bytes) + FCS (4 bytes).
       Only measurable at the network interface level.

TCP FRAMING — WHY AND HOW
--------------------------
TCP is a byte-stream protocol, NOT a message protocol.
A single recv() call may return:
  - Less than one message  (partial delivery — network split)
  - Exactly one message    (the happy path)
  - More than one message  (Nagle's algorithm batches small sends)
  - One complete message followed by a partial next message

We use newline-delimited JSON (NDJSON):
  Each message = one JSON object followed by b"\\n"

recv_message() maintains a per-connection bytearray buffer.
The buffer is created ONCE per connection and passed into every call.
Bytes remaining after extracting a complete message stay in the buffer
for the next call — no bytes are ever discarded.

VIVA TIPS
---------
  Q: Why not just use recv(4096) and assume it is one message?
  A: TCP does not preserve message boundaries. On a loaded LAN, or when
     sending large JSON payloads, the OS may deliver the data in multiple
     segments. Naive recv() would then return partial JSON and crash.

  Q: Why newline-delimited JSON instead of length-prefix framing?
  A: NDJSON is simpler to implement and debug (readable in Wireshark),
     uses only the standard library, and is reliable for our payload sizes.
     Length-prefix framing would need struct.pack/unpack and is better
     suited for binary protocols or very large payloads.
=============================================================================
"""

import json
import socket
from datetime import datetime

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Valid request type strings.
# Extend this set in later phases when new traffic types are added.
#
# Phase 4 additions:
#   COLLECTION_START -- instructs the server to begin writing the dataset
#   COLLECTION_STOP  -- instructs the server to stop writing the dataset
REQUEST_TYPES: set = {
    "DATA_REQUEST",
    "STATUS_REQUEST",
    "COLLECTION_START",   # Phase 4 -- begin dataset collection session
    "COLLECTION_STOP",    # Phase 4 -- end dataset collection session
}

# Every valid request must contain all of these keys.
REQUIRED_FIELDS: set = {
    "request_id",
    "timestamp",
    "request_type",
    "payload",
    "payload_size",
}

# ---------------------------------------------------------------------------
# Request ID counter
# ---------------------------------------------------------------------------
# A module-level counter gives each request a unique, incrementing ID.
# It is intentionally simple — no thread safety needed in Phase 2 because
# the client is single-threaded.
_request_counter: int = 0


def _next_request_id() -> str:
    """
    Return the next request ID in the format REQ-NNNN.
    The counter increments each time this function is called.
    """
    global _request_counter
    _request_counter += 1
    return f"REQ-{_request_counter:04d}"


# ---------------------------------------------------------------------------
# Build a request dict
# ---------------------------------------------------------------------------
def build_request(request_type: str, payload: str) -> dict:
    """
    Build and return a structured request dictionary.

    Parameters
    ----------
    request_type : str
        Must be one of REQUEST_TYPES (e.g. "DATA_REQUEST").
    payload : str
        The application data to send.

    Returns
    -------
    dict
        A request dict ready to pass to send_message().

    Notes on payload_size
    ---------------------
    payload_size is the UTF-8 byte length of the payload string.
    We use len(payload.encode("utf-8")) — NOT len(payload) — because
    Python's len() counts Unicode code points, not bytes on the wire.
    For ASCII text both are equal; for non-ASCII they differ.

    The server validates this value independently (Correction #4).
    """
    if request_type not in REQUEST_TYPES:
        raise ValueError(
            f"Unknown request_type '{request_type}'. "
            f"Valid types: {REQUEST_TYPES}"
        )

    # UTF-8 byte length — application-level payload size only.
    # This is NOT the TCP segment size or IP packet size.
    payload_bytes: int = len(payload.encode("utf-8"))

    return {
        "request_id":   _next_request_id(),
        "timestamp":    datetime.now().isoformat(),   # ISO-8601, local time
        "request_type": request_type,
        "payload":      payload,
        "payload_size": payload_bytes,                # UTF-8 bytes of payload
    }


# ---------------------------------------------------------------------------
# Build a response dict
# ---------------------------------------------------------------------------
def build_response(request_id: str, status: str, message: str) -> dict:
    """
    Build and return a structured response dictionary.

    Parameters
    ----------
    request_id : str
        Echo of the request's ID — allows the client to correlate
        the response to the specific request that triggered it.
    status : str
        "SUCCESS" or "ERROR"
    message : str
        Human-readable result detail.

    Notes on server_time
    --------------------
    server_time records when the SERVER processed the request.
    It is used ONLY for server-side log correlation and display.

    It must NOT be used to compute RTT, because client and server
    clocks may not be synchronized (NTP is not guaranteed on a LAN).
    RTT is measured on the client using time.perf_counter() (Correction #2).
    """
    return {
        "request_id":  request_id,
        "status":      status,         # "SUCCESS" or "ERROR"
        "message":     message,
        "server_time": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# TCP framing — send
# ---------------------------------------------------------------------------
def send_message(sock: socket.socket, data: dict) -> None:
    """
    Serialize a dict to JSON, append a newline byte, and send it all.

    The newline (b"\\n") is the message delimiter for our NDJSON framing.
    sendall() is used instead of send() to guarantee all bytes are
    transmitted even if the OS buffers them across multiple calls.

    Parameters
    ----------
    sock : socket.socket
        A connected TCP socket.
    data : dict
        The message dict to send (request or response).

    Raises
    ------
    OSError
        If the socket send fails (connection broken, etc.).
    """
    # Serialize to a compact JSON string (no extra whitespace) then encode
    # to UTF-8 bytes and append the newline delimiter.
    raw: bytes = json.dumps(data, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(raw)


# ---------------------------------------------------------------------------
# TCP framing — receive
# ---------------------------------------------------------------------------
def recv_message(
    sock: socket.socket,
    buf: bytearray,
    buffer_size: int,
) -> dict:
    """
    Read bytes from sock into buf until a newline delimiter is found.
    Return the parsed JSON dict for that complete message.
    Leave any remaining bytes in buf for the next call.

    Parameters
    ----------
    sock : socket.socket
        A connected TCP socket.
    buf : bytearray
        Per-connection receive buffer.
        MUST be created once per connection (bytearray()) and reused
        across all calls for the same connection.
        This is what makes partial-message and multi-message handling correct.
    buffer_size : int
        How many bytes to ask the OS for in each recv() call.

    Returns
    -------
    dict
        The parsed JSON message.

    Raises
    ------
    ConnectionError
        Client has disconnected (recv returned zero bytes).
    ValueError
        Bytes before the newline are not valid JSON.

    How the buffer works (example)
    --------------------------------
    Suppose two messages arrive merged in one recv():

      recv() returns: b'{"request_id":"REQ-0001",...}\\n{"request_id":"REQ-0002",...}\\n'

    After first call to recv_message():
      extracted : b'{"request_id":"REQ-0001",...}'
      buf holds : b'{"request_id":"REQ-0002",...}\\n'

    Second call does NOT call recv() again (newline already in buf):
      extracted : b'{"request_id":"REQ-0002",...}'
      buf holds : b''

    Suppose a message arrives split across two recv() calls:

      recv() #1 returns: b'{"request_id":"REQ-0001"'
      recv() #2 returns: b',...}\\n'

    First recv_message() call:
      No newline in buf after recv #1 → calls recv() again → gets remainder
      Now newline found → extracts full message → returns dict
    """
    while True:
        # Step 1 — Check whether a complete message is already in the buffer.
        newline_pos = buf.find(b"\n")
        if newline_pos != -1:
            # Extract everything before the newline.
            raw_message: bytes = bytes(buf[:newline_pos])

            # Remove the extracted message AND the newline from the buffer.
            # Everything after the newline stays for the next call.
            del buf[:newline_pos + 1]

            # Attempt to decode and parse.
            # Raises ValueError (subclass: json.JSONDecodeError) if malformed.
            try:
                return json.loads(raw_message.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON: {exc}") from exc

        # Step 2 — No newline yet; read more bytes from the socket.
        chunk: bytes = sock.recv(buffer_size)

        if not chunk:
            # recv() returning zero bytes means the peer closed the connection.
            raise ConnectionError("Client disconnected (recv returned empty bytes).")

        # Append new bytes to the buffer and loop back to check for newline.
        buf.extend(chunk)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_request(data: dict) -> tuple:
    """
    Validate a parsed request dict.

    Returns
    -------
    (True, "")
        Request is valid.
    (False, reason)
        Request is invalid; reason is a human-readable explanation.

    This function NEVER raises — the caller decides what to do.

    Checks performed
    ----------------
    1. data must be a dict
    2. All REQUIRED_FIELDS must be present
    3. request_type must be in REQUEST_TYPES
    4. payload_size must be a non-negative int
    5. payload_size must equal len(payload.encode("utf-8"))
       (server independently computes the UTF-8 byte length — Correction #4)
    """
    # Check 1 — must be a dict
    if not isinstance(data, dict):
        return False, "Request must be a JSON object, not a list or primitive."

    # Check 2 — all required fields present
    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        return False, f"Missing required fields: {sorted(missing)}"

    # Check 3 — valid request type
    if data["request_type"] not in REQUEST_TYPES:
        return False, (
            f"Unknown request_type '{data['request_type']}'. "
            f"Valid: {sorted(REQUEST_TYPES)}"
        )

    # Check 4 — payload_size must be a non-negative integer
    if not isinstance(data["payload_size"], int) or data["payload_size"] < 0:
        return False, "payload_size must be a non-negative integer."

    # Check 5 — payload_size must match the actual UTF-8 byte length.
    # We measure the application-level payload size independently.
    # This is NOT the TCP segment size or IP packet size.
    actual_size: int = len(data["payload"].encode("utf-8"))
    if data["payload_size"] != actual_size:
        return False, (
            f"payload_size mismatch: reported {data['payload_size']} bytes, "
            f"actual UTF-8 byte length is {actual_size} bytes."
        )

    return True, ""
