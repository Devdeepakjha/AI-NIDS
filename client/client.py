"""
=============================================================================
client.py  --  TCP Client  (Phase 4)
=============================================================================

PROJECT : AI-Based Network Intrusion Detection System
PHASE   : 4 -- Network Feature Extraction & Dataset Generation
RUN ON  : PC 1 (the "client" machine)

WHAT THIS FILE DOES (Phase 3)
------------------------------
1. Presents a 7-option terminal menu.
2. Options [1]-[2]: Phase 2 functionality (single/multiple requests).
3. Options [3]-[5]: NEW -- controlled traffic generation at target rates.
4. Option [6]: View connection information (renamed from Phase 2 option [3]).
5. Option [7]: Exit.

CHANGES FROM PHASE 2
---------------------
  Phase 2: 4-option menu (single, multiple, info, exit)
  Phase 3: 7-option menu adds Normal/Medium/High traffic generation

TRAFFIC GENERATION (Correction #1)
-------------------------------------
All traffic rates are TARGET rates, not guaranteed rates.

The client always reports both:
  - Target Rate  : what the user requested
  - Actual Rate  : what was actually achieved (measured via perf_counter)

The server's independently observed rate (in the monitor dashboard) is
the source of truth for how many requests actually arrived.

The implementation does NOT artificially force the displayed actual rate.
If Windows timer resolution (~15ms) or system load prevents achieving
the target rate, the actual measured rate is reported honestly.

RTT MEASUREMENT
---------------
RTT is measured EXCLUSIVELY on the client using time.perf_counter().
This is unchanged from Phase 2.

CN CONCEPTS COVERED (Phase 3 additions)
-----------------------------------------
  Controlled traffic generation  -- rate-limited request sending
  Rate limiting                  -- time.sleep() for inter-request pacing
  Performance measurement        -- target vs actual rate comparison
  Application-layer traffic      -- all traffic uses our JSON protocol
=============================================================================
"""

import socket
import sys
import os
import time
from datetime import datetime

# Ensure both client/ and project root are in sys.path
_CLIENT_DIR = os.path.abspath(os.path.dirname(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_CLIENT_DIR, ".."))
for _p in [_PROJECT_ROOT, _CLIENT_DIR]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import client.config as config
except ImportError:
    import config

import shared.protocol as protocol


def _safe_text(text: str) -> str:
    """Format text safely for the current stdout encoding to avoid cp1252 crashes."""
    encoding = sys.stdout.encoding or "utf-8"
    return str(text).encode(encoding, errors="replace").decode(encoding)


# ---------------------------------------------------------------------------
# Helper -- print a timestamped log line
# ---------------------------------------------------------------------------
def log(tag: str, message: str) -> None:
    """Print a formatted, timestamped log line to the terminal."""
    now = datetime.now().strftime("%H:%M:%S")
    safe_msg = _safe_text(message)
    print(f"[{now}] [{tag}] {safe_msg}")


# ---------------------------------------------------------------------------
# connect_to_server -- create a connected socket
# ---------------------------------------------------------------------------
def connect_to_server() -> socket.socket:
    """
    Create a TCP socket and connect to the configured server.
    Returns a connected client socket.
    Exits on connection failure.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    log("CLIENT", f"Connecting to {config.SERVER_IP}:{config.SERVER_PORT} ...")

    try:
        sock.connect((config.SERVER_IP, config.SERVER_PORT))
    except ConnectionRefusedError:
        log("CLIENT", "[ERROR] Connection REFUSED.")
        log("CLIENT", "  -> Is server.py running on PC 2?")
        log("CLIENT", "  -> Is SERVER_PORT correct in config.py?")
        sock.close()
        return None
    except socket.timeout:
        log("CLIENT", "[ERROR] Connection TIMED OUT.")
        log("CLIENT", "  -> Is SERVER_IP correct in config.py?")
        log("CLIENT", "  -> Are both PCs on the same LAN?")
        sock.close()
        return None
    except OSError as exc:
        log("CLIENT", f"[ERROR] OS error: {exc}")
        sock.close()
        return None

    # Remove timeout for data transfer (traffic generation may take seconds)
    sock.settimeout(None)

    log("CLIENT", "[OK] Connected successfully.")
    print()
    return sock


# ---------------------------------------------------------------------------
# send_single_request -- Phase 2, unchanged
# ---------------------------------------------------------------------------
def send_single_request(sock: socket.socket, buf: bytearray) -> bool:
    """
    Build one DATA_REQUEST, send it, receive and display the response.
    Measures RTT locally using time.perf_counter().
    """
    request = protocol.build_request(
        request_type="DATA_REQUEST",
        payload=config.DEFAULT_PAYLOAD,
    )

    print("  " + "-" * 44)
    log("CLIENT", "Sending request ...")
    log("CLIENT", f"  Request ID   : {request['request_id']}")
    log("CLIENT", f"  Type         : {request['request_type']}")
    log("CLIENT", f"  Timestamp    : {request['timestamp']}")
    log("CLIENT", f"  Payload size : {request['payload_size']} bytes (app-level, UTF-8)")
    log("CLIENT", f"  Payload      : {request['payload']}")
    print()

    t_start = time.perf_counter()

    try:
        protocol.send_message(sock, request)
    except OSError as exc:
        log("CLIENT", f"[ERROR] Failed to send: {exc}")
        return False

    try:
        response = protocol.recv_message(sock, buf, config.BUFFER_SIZE)
    except ConnectionError:
        log("CLIENT", "[ERROR] Server closed the connection unexpectedly.")
        return False
    except ValueError as exc:
        log("CLIENT", f"[ERROR] Could not parse server response: {exc}")
        return False

    t_end  = time.perf_counter()
    rtt_ms = (t_end - t_start) * 1000

    log("CLIENT", "Response received:")
    log("CLIENT", f"  Request ID   : {response.get('request_id', '?')}")
    log("CLIENT", f"  Status       : {response.get('status', '?')}")
    log("CLIENT", f"  Message      : {response.get('message', '?')}")
    log("CLIENT", f"  Server time  : {response.get('server_time', '?')}  (server-side log only)")
    log("CLIENT", f"  RTT          : {rtt_ms:.2f} ms  (measured locally via perf_counter)")
    print()

    return True


# ---------------------------------------------------------------------------
# send_multiple_requests -- Phase 2, unchanged
# ---------------------------------------------------------------------------
def send_multiple_requests(sock: socket.socket, buf: bytearray, count: int) -> None:
    """
    Send count sequential DATA_REQUEST messages on the same TCP connection.
    """
    log("CLIENT", f"Sending {count} sequential requests on one connection ...")
    print()

    successful = 0
    total_rtt  = 0.0

    for i in range(1, count + 1):
        request = protocol.build_request(
            request_type="DATA_REQUEST",
            payload=f"{config.DEFAULT_PAYLOAD} (request {i} of {count})",
        )

        t_start = time.perf_counter()

        try:
            protocol.send_message(sock, request)
            response = protocol.recv_message(sock, buf, config.BUFFER_SIZE)
        except (OSError, ConnectionError, ValueError) as exc:
            log("CLIENT", f"  Request {i} FAILED: {exc}")
            break

        rtt_ms = (time.perf_counter() - t_start) * 1000

        status = response.get("status", "?")
        log("CLIENT",
            f"  [{i:>3}/{count}] {request['request_id']}  "
            f"status={status}  "
            f"payload={request['payload_size']}B  "
            f"RTT={rtt_ms:.2f}ms")

        if status == "SUCCESS":
            successful += 1
            total_rtt += rtt_ms

    print()
    avg_rtt = (total_rtt / successful) if successful > 0 else 0.0
    log("CLIENT", f"Summary: {successful}/{count} requests successful")
    log("CLIENT", f"         Average RTT: {avg_rtt:.2f} ms (client-local perf_counter)")
    print()


# ---------------------------------------------------------------------------
# generate_traffic -- Phase 3 NEW
# ---------------------------------------------------------------------------
def generate_traffic(
    sock: socket.socket,
    buf: bytearray,
    target_rate: int,
    duration_sec: int,
    mode_name: str,
) -> None:
    """
    Send requests at approximately target_rate req/sec for duration_sec seconds.

    Uses the existing protocol.build_request() and protocol.send_message()
    so all generated traffic follows the SAME protocol as normal requests.

    Parameters
    ----------
    sock : socket.socket
        Connected TCP socket.
    buf : bytearray
        Per-connection receive buffer.
    target_rate : int
        Target requests per second.
        This is a TARGET, not a guarantee (Correction #1).
    duration_sec : int
        How many seconds to run.
    mode_name : str
        Display label ("NORMAL", "MEDIUM", "HIGH").

    Rate Limiting
    -------------
    For each request, we compute the expected time to the next request
    (interval = 1.0 / target_rate) and sleep for the remaining time
    after send+recv. If send+recv takes longer than the interval,
    we skip the sleep and send immediately.

    On Windows, time.sleep() has ~15ms granularity. This means:
      - NORMAL (10/s, 100ms interval): accurate
      - MEDIUM (100/s, 10ms interval): slightly affected
      - HIGH (500/s, 2ms interval): actual rate will be lower than 500

    The actual achieved rate is measured honestly and reported.
    The server's independently observed rate is the source of truth.
    """
    interval = 1.0 / target_rate if target_rate > 0 else 1.0

    print("  " + "-" * 50)
    log("CLIENT", f"Traffic Generation: {mode_name}")
    log("CLIENT", f"  Target Rate  : {target_rate} req/sec")
    log("CLIENT", f"  Duration     : {duration_sec} seconds")
    log("CLIENT", f"  Protocol     : DATA_REQUEST (same as normal)")
    print()

    sent = 0
    failed = 0
    total_payload_bytes = 0
    total_rtt = 0.0

    t_start = time.perf_counter()
    t_end   = t_start + duration_sec

    # Progress display interval (update every 1 second)
    next_progress = t_start + 1.0

    while time.perf_counter() < t_end:
        t_req_start = time.perf_counter()

        request = protocol.build_request(
            request_type="DATA_REQUEST",
            payload=f"Traffic test [{mode_name}] request #{sent + 1}",
        )

        try:
            protocol.send_message(sock, request)
            response = protocol.recv_message(sock, buf, config.BUFFER_SIZE)
        except (OSError, ConnectionError, ValueError):
            failed += 1
            continue

        t_req_end = time.perf_counter()
        rtt_ms = (t_req_end - t_req_start) * 1000

        if response.get("status") == "SUCCESS":
            sent += 1
            total_payload_bytes += request["payload_size"]
            total_rtt += rtt_ms
        else:
            failed += 1

        # Progress update every ~1 second
        now = time.perf_counter()
        if now >= next_progress:
            elapsed = now - t_start
            current_rate = sent / elapsed if elapsed > 0 else 0
            remaining = max(0, duration_sec - elapsed)
            log("CLIENT",
                f"  [PROGRESS] {sent} sent  |  "
                f"rate: {current_rate:.1f} req/s  |  "
                f"{remaining:.0f}s remaining")
            next_progress = now + 1.0

        # Rate limiting: sleep for remaining interval time
        elapsed_req = time.perf_counter() - t_req_start
        sleep_time = interval - elapsed_req
        if sleep_time > 0:
            time.sleep(sleep_time)

    # Final measurement
    actual_duration = time.perf_counter() - t_start
    actual_rate = sent / actual_duration if actual_duration > 0 else 0

    # Summary
    print()
    log("CLIENT", "Traffic Generation Complete")
    print("  " + "-" * 50)
    log("CLIENT", f"  Mode               : {mode_name}")
    log("CLIENT", f"  Target Rate        : {target_rate} req/sec")
    log("CLIENT", f"  Actual Rate        : {actual_rate:.1f} req/sec")
    log("CLIENT", f"  Duration           : {actual_duration:.1f} seconds")
    log("CLIENT", f"  Requests Sent      : {sent}")
    log("CLIENT", f"  Requests Failed    : {failed}")
    log("CLIENT", f"  Total Payload      : {total_payload_bytes} bytes (app-level, UTF-8)")
    if sent > 0:
        avg_rtt = total_rtt / sent
        log("CLIENT", f"  Avg RTT            : {avg_rtt:.2f} ms (client-local perf_counter)")
    print()
    log("CLIENT", "  NOTE: The server's observed rate (in monitor dashboard)")
    log("CLIENT", "        is the source of truth for actual traffic received.")
    print()


# ---------------------------------------------------------------------------
# show_connection_info -- Phase 2, unchanged
# ---------------------------------------------------------------------------
def show_connection_info(sock: socket.socket) -> None:
    """Display the current socket's local and remote addresses."""
    local_ip, local_port   = sock.getsockname()
    remote_ip, remote_port = sock.getpeername()

    print()
    print("  +------------------------------------------+")
    print("  |         CONNECTION INFORMATION           |")
    print("  +------------------------------------------+")
    print(f"  Local  (this PC)  : {local_ip}:{local_port}")
    print(f"  Remote (server)   : {remote_ip}:{remote_port}")
    print(f"  Protocol          : TCP / IPv4")
    print(f"  Recv buffer size  : {config.BUFFER_SIZE} bytes (OS-level)")
    print(f"  Note              : Local port {local_port} is an ephemeral port,")
    print(f"                      assigned automatically by the OS.")
    print("  +------------------------------------------+")
    print()


# ---------------------------------------------------------------------------
# send_collection_control -- Phase 4 NEW
# ---------------------------------------------------------------------------
def send_collection_control(sock: socket.socket, buf: bytearray, start: bool) -> None:
    """
    Send COLLECTION_START or COLLECTION_STOP to the server.

    Parameters
    ----------
    sock : socket.socket
        Connected TCP socket.
    buf : bytearray
        Per-connection receive buffer.
    start : bool
        True  → COLLECTION_START  (begin writing the dataset)
        False → COLLECTION_STOP   (stop writing the dataset)

    The server responds with SUCCESS and the assigned experiment ID
    (on START) or the total rows written so far (on STOP).
    """
    req_type = "COLLECTION_START" if start else "COLLECTION_STOP"
    action   = "START" if start else "STOP"

    request = protocol.build_request(
        request_type=req_type,
        payload=f"Dataset collection {action} command.",
    )

    print("  " + "-" * 44)
    log("CLIENT", f"Sending dataset collection {action} command ...")

    try:
        protocol.send_message(sock, request)
        response = protocol.recv_message(sock, buf, config.BUFFER_SIZE)
    except (OSError, ConnectionError, ValueError) as exc:
        log("CLIENT", f"[ERROR] Collection {action} command failed: {exc}")
        print()
        return

    log("CLIENT", f"  Status  : {response.get('status', '?')}")
    log("CLIENT", f"  Message : {response.get('message', '?')}")
    print()


# ---------------------------------------------------------------------------
# run_menu -- main client loop
# ---------------------------------------------------------------------------
def run_menu() -> None:
    """
    Display the Phase 3 client menu and handle user input.
    """
    print()
    print("+------------------------------------------+")
    print("|    AI-NIDS -- TCP CLIENT  (Phase 4)      |")
    print("+------------------------------------------+")
    print(f"  Server : {config.SERVER_IP}:{config.SERVER_PORT}")
    print()

    while True:
        print("  [1] Send Normal Request")
        print("  [2] Send Multiple Requests")
        print("  [3] Generate Normal Traffic")
        print("  [4] Generate Medium Traffic")
        print("  [5] Generate High Traffic")
        print("  [6] Start Dataset Collection")
        print("  [7] Stop Dataset Collection")
        print("  [8] View Connection Information")
        print("  [9] Exit")
        print()

        choice = input("  Choice: ").strip()
        print()

        # ------------------------------------------------------------------
        # Option 1 -- single request (Phase 2, unchanged)
        # ------------------------------------------------------------------
        if choice == "1":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            send_single_request(sock, buf)
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 2 -- multiple requests (Phase 2, unchanged)
        # ------------------------------------------------------------------
        elif choice == "2":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            send_multiple_requests(sock, buf, config.MULTI_REQUEST_COUNT)
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 3 -- Normal Traffic (~10 req/sec)
        # ------------------------------------------------------------------
        elif choice == "3":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            generate_traffic(
                sock, buf,
                target_rate=config.NORMAL_RATE,
                duration_sec=config.TRAFFIC_DURATION,
                mode_name="NORMAL",
            )
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 4 -- Medium Traffic (~100 req/sec)
        # ------------------------------------------------------------------
        elif choice == "4":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            generate_traffic(
                sock, buf,
                target_rate=config.MEDIUM_RATE,
                duration_sec=config.TRAFFIC_DURATION,
                mode_name="MEDIUM",
            )
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 5 -- High Traffic (~500 req/sec target)
        # ------------------------------------------------------------------
        elif choice == "5":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            generate_traffic(
                sock, buf,
                target_rate=config.HIGH_RATE,
                duration_sec=config.TRAFFIC_DURATION,
                mode_name="HIGH",
            )
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 6 -- Start Dataset Collection (Phase 4 NEW)
        # ------------------------------------------------------------------
        elif choice == "6":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            send_collection_control(sock, buf, start=True)
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 7 -- Stop Dataset Collection (Phase 4 NEW)
        # ------------------------------------------------------------------
        elif choice == "7":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            send_collection_control(sock, buf, start=False)
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 8 -- View Connection Information (was option 6)
        # ------------------------------------------------------------------
        elif choice == "8":
            sock = connect_to_server()
            if sock is None:
                continue
            buf = bytearray()
            show_connection_info(sock)
            sock.close()
            log("CLIENT", "Connection closed.")
            print()

        # ------------------------------------------------------------------
        # Option 9 -- Exit (was option 7)
        # ------------------------------------------------------------------
        elif choice == "9":
            log("CLIENT", "Exiting. Goodbye.")
            print()
            break

        else:
            log("CLIENT", f"Unknown choice '{choice}'. Please enter 1-9.")
            print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run_menu()
