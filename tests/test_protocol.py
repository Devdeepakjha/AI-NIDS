"""
=============================================================================
tests/test_protocol.py  —  Unit Tests for shared/protocol.py  (Phase 2)
=============================================================================

PURPOSE
-------
Verify that shared/protocol.py behaves correctly for all expected cases
WITHOUT requiring a live network connection.

TCP framing is tested by simulating socket.recv() using a custom stub
class that yields bytes in controlled chunks — mimicking partial delivery,
merged delivery, etc.

RUN
---
From the project root directory:
    python tests/test_protocol.py

All tests run inline and print PASS / FAIL for each case.
Exit code is 0 if all pass, 1 if any fail.

TESTS
-----
 1. build_request() — valid request structure and field types
 2. build_request() — payload_size is UTF-8 byte count (not char count)
 3. build_response() — valid response structure
 4. validate_request() — accepts a fully valid request
 5. validate_request() — rejects a missing required field
 6. validate_request() — rejects an invalid request_type
 7. validate_request() — rejects payload_size mismatch (UTF-8 bytes)
 8. recv_message() — handles a complete message in one chunk
 9. recv_message() — handles a message split across two chunks (partial delivery)
10. recv_message() — handles two messages merged in one chunk
=============================================================================
"""

import sys
import os

# Allow import of shared/protocol.py from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import shared.protocol as protocol


# ---------------------------------------------------------------------------
# Minimal socket stub for testing recv_message() without a real network
# ---------------------------------------------------------------------------
class _FakeSocket:
    """
    Simulates socket.recv() by returning pre-loaded byte chunks in sequence.
    Mimics TCP partial delivery and merged-message scenarios.
    """

    def __init__(self, chunks: list):
        """
        Parameters
        ----------
        chunks : list of bytes
            Each element is what one recv() call returns.
            An empty bytes b"" signals EOF (peer disconnected).
        """
        self._chunks = list(chunks)

    def recv(self, _buffer_size: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""   # EOF


# ---------------------------------------------------------------------------
# Test runner helpers
# ---------------------------------------------------------------------------
_results = []


def _pass(name: str) -> None:
    print(f"  [PASS] {name}")
    _results.append(True)


def _fail(name: str, reason: str) -> None:
    print(f"  [FAIL] {name}")
    print(f"         Reason: {reason}")
    _results.append(False)


def _run(name: str, fn):
    try:
        fn()
        _pass(name)
    except AssertionError as exc:
        _fail(name, str(exc))
    except Exception as exc:
        _fail(name, f"Unexpected exception: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_build_request_structure():
    """build_request() returns a dict with all required fields."""
    req = protocol.build_request("DATA_REQUEST", "hello")
    for field in protocol.REQUIRED_FIELDS:
        assert field in req, f"Missing field: {field}"
    assert req["request_type"] == "DATA_REQUEST"
    assert req["payload"] == "hello"
    assert req["request_id"].startswith("REQ-")


def test_build_request_payload_size_utf8():
    """
    payload_size must be len(payload.encode('utf-8')), not len(payload).
    For ASCII text they are equal; this test uses a multi-byte Unicode char
    to distinguish the two.
    """
    # U+00E9 (é) is 1 char but 2 UTF-8 bytes
    payload = "caf\u00e9"        # 4 characters, 5 UTF-8 bytes
    req = protocol.build_request("DATA_REQUEST", payload)
    expected_bytes = len(payload.encode("utf-8"))   # 5
    assert req["payload_size"] == expected_bytes, (
        f"Expected payload_size={expected_bytes}, got {req['payload_size']}"
    )


def test_build_response_structure():
    """build_response() returns a dict with all required response fields."""
    resp = protocol.build_response("REQ-0001", "SUCCESS", "OK")
    assert resp["request_id"] == "REQ-0001"
    assert resp["status"] == "SUCCESS"
    assert resp["message"] == "OK"
    assert "server_time" in resp


def test_validate_request_valid():
    """validate_request() accepts a fully correct request."""
    payload = "hello"
    req = {
        "request_id":   "REQ-0001",
        "timestamp":    "2026-08-21T21:00:00",
        "request_type": "DATA_REQUEST",
        "payload":      payload,
        "payload_size": len(payload.encode("utf-8")),
    }
    ok, reason = protocol.validate_request(req)
    assert ok, f"Expected valid, got error: {reason}"


def test_validate_request_missing_field():
    """validate_request() rejects a request missing a required field."""
    req = {
        "request_id":   "REQ-0001",
        "timestamp":    "2026-08-21T21:00:00",
        # request_type missing
        "payload":      "hello",
        "payload_size": 5,
    }
    ok, reason = protocol.validate_request(req)
    assert not ok, "Expected invalid, but got valid"
    assert "request_type" in reason or "Missing" in reason


def test_validate_request_invalid_type():
    """validate_request() rejects an unknown request_type."""
    payload = "hello"
    req = {
        "request_id":   "REQ-0001",
        "timestamp":    "2026-08-21T21:00:00",
        "request_type": "HACK_ATTEMPT",    # not in REQUEST_TYPES
        "payload":      payload,
        "payload_size": len(payload.encode("utf-8")),
    }
    ok, reason = protocol.validate_request(req)
    assert not ok, "Expected invalid, but got valid"
    assert "HACK_ATTEMPT" in reason or "Unknown" in reason


def test_validate_request_payload_size_mismatch():
    """
    validate_request() rejects a request where payload_size
    does not match the actual UTF-8 byte length of payload.
    """
    req = {
        "request_id":   "REQ-0001",
        "timestamp":    "2026-08-21T21:00:00",
        "request_type": "DATA_REQUEST",
        "payload":      "hello",
        "payload_size": 999,   # wrong — actual UTF-8 size is 5
    }
    ok, reason = protocol.validate_request(req)
    assert not ok, "Expected invalid due to payload_size mismatch"
    assert "mismatch" in reason.lower() or "5" in reason


def test_recv_message_complete_in_one_chunk():
    """recv_message() handles a single complete message arriving in one recv()."""
    msg = {"request_id": "REQ-0001", "status": "SUCCESS"}
    import json
    raw = json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"
    sock = _FakeSocket([raw])
    buf  = bytearray()
    result = protocol.recv_message(sock, buf, 4096)
    assert result["request_id"] == "REQ-0001"
    assert len(buf) == 0, "Buffer should be empty after consuming the only message"


def test_recv_message_split_across_two_chunks():
    """
    recv_message() correctly assembles a message split across two recv() calls.
    This simulates TCP partial delivery (e.g. large payload split by the OS).
    """
    import json
    msg  = {"request_id": "REQ-0002", "value": "x" * 50}
    raw  = json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"
    half = len(raw) // 2
    # Split into two chunks — no newline in first chunk
    sock = _FakeSocket([raw[:half], raw[half:]])
    buf  = bytearray()
    result = protocol.recv_message(sock, buf, 4096)
    assert result["request_id"] == "REQ-0002"


def test_recv_message_two_merged_in_one_chunk():
    """
    recv_message() correctly separates two messages merged in a single recv().
    This simulates Nagle's algorithm batching two small sends together.
    """
    import json
    msg1 = {"request_id": "REQ-0003", "n": 1}
    msg2 = {"request_id": "REQ-0004", "n": 2}
    raw1 = json.dumps(msg1, separators=(",", ":")).encode("utf-8") + b"\n"
    raw2 = json.dumps(msg2, separators=(",", ":")).encode("utf-8") + b"\n"
    # Both messages arrive in a single recv() call
    sock = _FakeSocket([raw1 + raw2])
    buf  = bytearray()

    result1 = protocol.recv_message(sock, buf, 4096)
    assert result1["request_id"] == "REQ-0003", f"Got: {result1}"

    # Second call should consume from buf without calling recv() again
    result2 = protocol.recv_message(sock, buf, 4096)
    assert result2["request_id"] == "REQ-0004", f"Got: {result2}"
    assert len(buf) == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print()
    print("+------------------------------------------+")
    print("|  AI-NIDS  --  Protocol Unit Tests        |")
    print("+------------------------------------------+")
    print()

    _run("1. build_request() structure",              test_build_request_structure)
    _run("2. build_request() payload_size (UTF-8)",   test_build_request_payload_size_utf8)
    _run("3. build_response() structure",             test_build_response_structure)
    _run("4. validate_request() — valid",             test_validate_request_valid)
    _run("5. validate_request() — missing field",     test_validate_request_missing_field)
    _run("6. validate_request() — invalid type",      test_validate_request_invalid_type)
    _run("7. validate_request() — payload_size mismatch", test_validate_request_payload_size_mismatch)
    _run("8. recv_message() — complete in one chunk", test_recv_message_complete_in_one_chunk)
    _run("9. recv_message() — split across two chunks", test_recv_message_split_across_two_chunks)
    _run("10. recv_message() — two merged in one chunk", test_recv_message_two_merged_in_one_chunk)

    print()
    passed = sum(_results)
    total  = len(_results)
    print(f"  Result: {passed}/{total} tests passed.")
    print()

    sys.exit(0 if passed == total else 1)
