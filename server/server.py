"""
=============================================================================
server.py  --  TCP Server  (Phase 4)
=============================================================================

PROJECT : AI-Based Network Intrusion Detection System
PHASE   : 4 -- Network Feature Extraction & Dataset Generation
RUN ON  : PC 2 (the "server" machine)

WHAT THIS FILE DOES (Phase 3)
------------------------------
1. Creates a TCP server socket (same as Phase 1/2).
2. Binds to 0.0.0.0:5000 -- reachable from any LAN interface.
3. Starts the TrafficMonitor (background thread for dashboard display).
4. Accepts client connections.
5. Receives structured JSON requests using protocol.recv_message().
6. Validates each request using protocol.validate_request().
7. Records each valid request in the monitor (for aggregate metrics).
8. Sends a structured JSON response.
9. Handles malformed JSON -- returns ERROR response, keeps connection open.
10. Handles client disconnect gracefully.
11. Loops back for the next client.

CHANGES FROM PHASE 2
---------------------
  Phase 2: per-request verbose logging to terminal
  Phase 3: monitor.record_request() on each valid request;
           verbose logging suppressed when traffic rate exceeds threshold;
           monitor dashboard displayed by background thread

The socket creation, bind, listen, and accept loop are UNCHANGED.
handle_client() core logic is UNCHANGED -- three hook calls added:
  monitor.record_connect()   at session start
  monitor.record_request()   after each valid request
  monitor.record_disconnect() at session end

CN CONCEPTS COVERED (Phase 3 additions)
-----------------------------------------
  Application-layer traffic monitoring -- measuring our own protocol traffic
  Thread safety                        -- lock-based synchronization
  Real-time observation                -- live metrics from actual requests
  Aggregate measurement                -- rates computed from cumulative counters
=============================================================================
"""

import socket
import sys
import os
import time
from datetime import datetime

# Ensure both server/ and project root are in sys.path
_SERVER_DIR = os.path.abspath(os.path.dirname(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_SERVER_DIR, ".."))
for _p in [_PROJECT_ROOT, _SERVER_DIR]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import server.config as config
except ImportError:
    import config

import shared.protocol as protocol

try:
    from server.monitor import TrafficMonitor
    from server.dataset_writer import DatasetWriter
except ImportError:
    from monitor import TrafficMonitor
    from dataset_writer import DatasetWriter


# ---------------------------------------------------------------------------
# Module-level instances
# ---------------------------------------------------------------------------
# Both created once at startup.  All handle_client() calls share them.
#
# _PROJECT_ROOT     -- absolute path to the repository root (one level up
#                      from this file), used to resolve the dataset path
#                      regardless of the working directory.
# _DATASET_ABS_PATH -- absolute path to data/network_traffic.csv
# dataset_writer    -- Phase 4 CSV writer (passed into TrafficMonitor)
# monitor           -- Phase 3/4 traffic monitor
# ---------------------------------------------------------------------------
_PROJECT_ROOT     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_DATASET_ABS_PATH = os.path.join(_PROJECT_ROOT, config.DATASET_PATH)

dataset_writer = DatasetWriter(_DATASET_ABS_PATH)
monitor        = TrafficMonitor(interval=config.MONITOR_INTERVAL,
                                dataset_writer=dataset_writer)

# Phase 6: Real-time feature extraction & detection bridge
try:
    from ml.feature_bridge import LiveDetectionBridge
    detection_bridge = LiveDetectionBridge()
except Exception:
    detection_bridge = None


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
# handle_client -- process all requests from one connected client
# ---------------------------------------------------------------------------
def handle_client(conn: socket.socket, addr: tuple) -> None:
    """
    Handle one client connection -- receive, validate, respond, repeat.

    Parameters
    ----------
    conn : socket.socket
        The connected socket returned by accept().
    addr : tuple
        (ip_address, port_number) of the remote client.

    Connection lifecycle
    --------------------
    The connection stays open until:
      a) The client disconnects (recv returns empty bytes).
      b) MAX_REQUESTS_PER_SESSION requests have been processed.
      c) An unrecoverable socket error occurs.

    Phase 3 additions:
      - monitor.record_connect() at start
      - monitor.record_request() on each valid request
      - monitor.record_disconnect() at end
      - Verbose per-request logging suppressed when traffic rate > threshold
    """
    client_ip   = addr[0]
    client_port = addr[1]

    # --- Phase 3: record connection event ---
    monitor.record_connect(client_ip)
    if detection_bridge:
        detection_bridge.on_connect(client_ip, client_port, server_port=config.PORT)

    # Per-connection receive buffer (Phase 2 -- unchanged)
    buf = bytearray()
    request_count = 0

    try:
        while request_count < config.MAX_REQUESTS_PER_SESSION:

            # ----------------------------------------------------------------
            # RECEIVE
            # ----------------------------------------------------------------
            try:
                data = protocol.recv_message(conn, buf, config.BUFFER_SIZE)
            except ConnectionError:
                break
            except ValueError as exc:
                error_resp = protocol.build_response(
                    request_id="UNKNOWN",
                    status="ERROR",
                    message="Malformed JSON -- could not parse request.",
                )
                try:
                    protocol.send_message(conn, error_resp)
                except OSError:
                    break
                continue

            # ----------------------------------------------------------------
            # VALIDATE
            # ----------------------------------------------------------------
            valid, reason = protocol.validate_request(data)
            if not valid:
                error_resp = protocol.build_response(
                    request_id=data.get("request_id", "UNKNOWN"),
                    status="ERROR",
                    message=f"Validation failed: {reason}",
                )
                try:
                    protocol.send_message(conn, error_resp)
                except OSError:
                    break
                continue

            # ----------------------------------------------------------------
            # Phase 4: Route collection-control commands
            # These are NOT recorded in the traffic monitor so they do not
            # inflate the traffic statistics dataset.
            # ----------------------------------------------------------------
            req_type = data["request_type"]

            if req_type == "COLLECTION_START":
                request_count += 1
                exp_id = dataset_writer.start_session()
                log("SERVER", f"[Phase 4] Dataset collection STARTED -- {exp_id}")
                log("SERVER", f"           Appending to: {config.DATASET_PATH}")
                ctrl_resp = protocol.build_response(
                    request_id=data["request_id"],
                    status="SUCCESS",
                    message=f"Collection started. Experiment ID: {exp_id}",
                )
                try:
                    protocol.send_message(conn, ctrl_resp)
                except OSError:
                    break
                continue

            if req_type == "COLLECTION_STOP":
                request_count += 1
                rows_so_far = dataset_writer.rows_written
                dataset_writer.stop_session()
                log("SERVER", f"[Phase 4] Dataset collection STOPPED -- "
                             f"{rows_so_far} rows written.")
                ctrl_resp = protocol.build_response(
                    request_id=data["request_id"],
                    status="SUCCESS",
                    message=f"Collection stopped. Rows written: {rows_so_far}",
                )
                try:
                    protocol.send_message(conn, ctrl_resp)
                except OSError:
                    break
                continue

            # ----------------------------------------------------------------
            # RECORD + LOG  (normal DATA_REQUEST / STATUS_REQUEST)
            # Phase 3 logic unchanged
            # ----------------------------------------------------------------
            request_count += 1
            app_payload_size = data["payload_size"]

            # Phase 3: record in monitor (aggregate counters only)
            monitor.record_request(client_ip, app_payload_size)
            if detection_bridge:
                detection_bridge.on_request(client_ip, client_port, app_payload_size)

            # Verbose per-request logging only when traffic is slow enough
            # to read. During traffic generation the monitor dashboard
            # shows the live metrics instead.
            if monitor.requests_per_sec < config.VERBOSE_LOG_THRESHOLD:
                print("  " + "-" * 44)
                log("SERVER", f"Request #{request_count} received")
                log("SERVER", f"  Request ID   : {data['request_id']}")
                log("SERVER", f"  Type         : {data['request_type']}")
                log("SERVER", f"  Client       : {client_ip}:{client_port}")
                log("SERVER", f"  Timestamp    : {data['timestamp']}")
                log("SERVER", f"  Payload size : {app_payload_size} bytes (app-level, UTF-8)")
                log("SERVER", f"  Payload      : {data['payload'][:60]}"
                             + ("..." if len(data["payload"]) > 60 else ""))
                print()

            # ----------------------------------------------------------------
            # RESPOND
            # ----------------------------------------------------------------
            response = protocol.build_response(
                request_id=data["request_id"],
                status="SUCCESS",
                message="Request processed successfully.",
            )
            try:
                protocol.send_message(conn, response)
                if detection_bridge:
                    resp_bytes = len(str(response).encode("utf-8"))
                    detection_bridge.on_response(client_ip, client_port, resp_bytes)
            except OSError:
                break

            if monitor.requests_per_sec < config.VERBOSE_LOG_THRESHOLD:
                log("SERVER", f"  Response     : SUCCESS  (server_time: {response['server_time']})")
                print()

    except OSError:
        pass
    except Exception as exc:
        log("SERVER", f"[WARN] Session error with client {client_ip}: {exc}")

    finally:
        conn.close()
        # Phase 3: record disconnection event
        monitor.record_disconnect(client_ip)
        if detection_bridge:
            detection_bridge.on_disconnect(client_ip, client_port)


# ---------------------------------------------------------------------------
# start_server -- main entry point
# ---------------------------------------------------------------------------
def start_server() -> None:
    """
    Create the server socket, bind, listen, start monitor, accept clients.
    """

    print()
    print("+------------------------------------------+")
    print("|    AI-NIDS -- TCP SERVER  (Phase 4)      |")
    print("+------------------------------------------+")
    print()

    # Create TCP/IPv4 socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((config.HOST, config.PORT))
    except OSError as exc:
        log("SERVER", f"FATAL -- Cannot bind to port {config.PORT}: {exc}")
        log("SERVER", "Is another process using this port?")
        sys.exit(1)

    log("SERVER", f"Bound to {config.HOST}:{config.PORT}")
    log("SERVER", f"Max requests per session : {config.MAX_REQUESTS_PER_SESSION}")
    log("SERVER", f"Monitor refresh interval : {config.MONITOR_INTERVAL}s")
    log("SERVER", f"Dataset path             : {config.DATASET_PATH}")
    log("SERVER", "Client [6] = Start Collection   [7] = Stop Collection")

    server_socket.listen(config.BACKLOG)

    log("SERVER", f"Listening ... (backlog = {config.BACKLOG})")
    log("SERVER", "Press Ctrl+C to stop.")
    print()

    # Phase 3: start the traffic monitor dashboard
    monitor.start()

    try:
        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)

    except KeyboardInterrupt:
        print()
        log("SERVER", "Shutdown requested (Ctrl+C).")

    finally:
        monitor.stop()
        server_socket.close()
        log("SERVER", "Server stopped.")
        print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    start_server()
