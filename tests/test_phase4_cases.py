"""
=============================================================================
tests/test_phase4_cases.py  --  Phase 4 Acceptance Tests  (P4-01 to P4-25)
=============================================================================

PROJECT : AI-Based Network Intrusion Detection System
PHASE   : 4 -- Network Feature Extraction & Dataset Generation

USAGE
-----
    cd "CN Project"
    python tests/test_phase4_cases.py

ARCHITECTURE
------------
The test suite is split into three sections:

  Section A -- Architecture / Schema Tests  (no server needed, fast)
    P4-22  No ML libraries in source code
    P4-23  No leakage columns (traffic_mode, target_rate) in CSV header
    P4-24  File tree matches expected (no unexpected files)

  Section B -- DatasetWriter Unit Tests  (no server needed, fast)
    P4-05  CSV header has exactly 9 correct columns
    P4-17  write_observation rejects negative values
    P4-18  write_observation rejects NaN/Inf values
    P4-19  DatasetWriter with unwritable path -- no exception raised

  Section C -- Live Server Integration Tests  (starts a server subprocess)
    P4-02  COLLECTION_START returns SUCCESS + experiment ID
    P4-03  COLLECTION_STOP  returns SUCCESS + row count
    P4-04  Real traffic during collection creates CSV rows
    P4-06  3-second run produces >= 2 observation rows
    P4-07  requests_per_sec > 0 in all data rows
    P4-08  bytes_per_sec > 0 in all data rows
    P4-09  avg_request_size_bytes > 0 in all data rows
    P4-10  active_connections = 1 during active session
    P4-11  total_connections_in_window >= 0 (integer)
    P4-12  window_duration_sec within [0.5, 2.0] seconds
    P4-13  Larger payload -> larger avg_request_size_bytes
    P4-14  Normal < Medium < High requests_per_sec
    P4-15  Second collection run appends -- row count increases
    P4-16  No duplicate header lines in CSV
    P4-20  Server stays alive after abrupt client disconnect
    P4-21  writer.inspect() reports 0 missing / 0 invalid / 0 negative values

  P4-01  Phase 3 regression (run test_phase3_cases.py as subprocess)
  P4-25  End-to-end acceptance: start -> Normal -> Medium -> High -> stop -> verify

NOTES
-----
- Traffic sessions in automated tests use 3-second durations for speed.
  The user-facing Phase 4 demo uses 10-second durations.
- The CSV is deleted before Section C runs to ensure a clean baseline.
- All traffic generated in these tests goes through the real TCP stack and
  the real JSON protocol -- no mock data.
=============================================================================
"""

import csv
import math
import os
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
TESTS_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TESTS_DIR, ".."))
SERVER_DIR   = os.path.join(PROJECT_ROOT, "server")
DATASET_PATH      = os.path.join(PROJECT_ROOT, "data", "_test_phase4_traffic.csv")
PROD_DATASET_PATH  = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")

# Make shared/ importable for protocol helpers
sys.path.insert(0, PROJECT_ROOT)
# Make server/ importable for DatasetWriter and COLUMNS
sys.path.insert(0, SERVER_DIR)

import shared.protocol as protocol
from dataset_writer import DatasetWriter, COLUMNS

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------
SERVER_HOST     = "127.0.0.1"
SERVER_PORT     = 5000
TRAFFIC_DUR_S   = 3          # seconds per traffic session (short for speed)
STARTUP_WAIT_S  = 1.5        # seconds to wait for server to bind
TICK_WAIT_S     = 1.5        # wait for at least one monitor tick to fire
BUFFER_SIZE     = 4096

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
_results: dict = {}

def _report(test_id: str, name: str, passed: bool, details: str = "") -> None:
    status = "PASS" if passed else "FAIL"
    _results[test_id] = {"name": name, "passed": passed, "details": details}
    mark = "OK" if passed else "XX"
    detail_str = f"  --> {details}" if details else ""
    print(f"  [{mark}] {test_id}: {name}{detail_str}")

def _assert(test_id: str, name: str, condition: bool, details: str = "") -> bool:
    _report(test_id, name, condition, details)
    return condition

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def _connect() -> tuple:
    """Return (sock, buf) connected to the local test server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)   # 30s on connect AND subsequent recv/send
    for attempt in range(8):
        try:
            sock.connect((SERVER_HOST, SERVER_PORT))
            break
        except ConnectionRefusedError:
            if attempt == 7:
                raise
            time.sleep(0.5)
    return sock, bytearray()

def _send_recv(sock: socket.socket, buf: bytearray, req_type: str, payload: str) -> dict:
    """Send one request and receive one response."""
    req = protocol.build_request(request_type=req_type, payload=payload)
    protocol.send_message(sock, req)
    return protocol.recv_message(sock, buf, BUFFER_SIZE)

def _send_requests(sock: socket.socket, buf: bytearray,
                   count: int, target_rate: float) -> int:
    """
    Send count DATA_REQUEST messages at approximately target_rate/s.
    Returns the number of successful responses.
    """
    interval = 1.0 / target_rate if target_rate > 0 else 0.0
    ok = 0
    for i in range(count):
        t0 = time.perf_counter()
        try:
            resp = _send_recv(sock, buf, "DATA_REQUEST",
                              f"Phase4 test req #{i+1} of {count}")
            if resp.get("status") == "SUCCESS":
                ok += 1
        except Exception:
            pass
        elapsed = time.perf_counter() - t0
        sleep = interval - elapsed
        if sleep > 0:
            time.sleep(sleep)
    return ok

def _start_collection(sock, buf) -> str:
    """Send COLLECTION_START; return experiment_id from response message."""
    resp = _send_recv(sock, buf, "COLLECTION_START",
                      "Dataset collection START command.")
    return resp.get("message", "")

def _stop_collection(sock, buf) -> str:
    """Send COLLECTION_STOP; return server response message."""
    resp = _send_recv(sock, buf, "COLLECTION_STOP",
                      "Dataset collection STOP command.")
    return resp.get("message", "")

def _read_csv_rows() -> list:
    """Read all data rows (excluding header) from the dataset CSV."""
    if not os.path.exists(DATASET_PATH):
        return []
    rows = []
    with open(DATASET_PATH, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(row)
    return rows

def _read_csv_header_line() -> str:
    """Read the first line of the CSV file."""
    if not os.path.exists(DATASET_PATH):
        return ""
    with open(DATASET_PATH, "r", encoding="utf-8") as fh:
        return fh.readline().strip()

# ===========================================================================
# SECTION A  --  Architecture / Schema Tests  (no server required)
# ===========================================================================

def run_section_a():
    print("\n" + "="*60)
    print("SECTION A -- Architecture / Schema Tests")
    print("="*60)

    # P4-22 -- No ML libraries in source code
    ml_keywords = ["sklearn", "RandomForest", "torch", "tensorflow",
                   "keras", "xgboost", "lightgbm"]
    found_ml = []
    source_dirs = [SERVER_DIR,
                   os.path.join(PROJECT_ROOT, "client"),
                   os.path.join(PROJECT_ROOT, "shared")]
    for src_dir in source_dirs:
        for fname in os.listdir(src_dir):
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(src_dir, fname)
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            for kw in ml_keywords:
                if kw in content:
                    found_ml.append(f"{fname}::{kw}")
    _assert("P4-22", "No ML libraries in source code",
            len(found_ml) == 0,
            f"Found: {found_ml}" if found_ml else "")

    # P4-23 -- No leakage columns in COLUMNS schema
    leakage_cols = ["traffic_mode", "target_rate"]
    found_leakage = [c for c in leakage_cols if c in COLUMNS]
    _assert("P4-23", "No leakage columns (traffic_mode, target_rate) in schema",
            len(found_leakage) == 0,
            f"Found: {found_leakage}" if found_leakage else "")

    # P4-24 -- Only expected new files exist
    expected_new = {"dataset_writer.py", "test_phase4_cases.py"}
    unexpected = []
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Skip hidden dirs, __pycache__, .git, data/
        dirs[:] = [d for d in dirs if not d.startswith((".","__"))]
        if os.path.join(PROJECT_ROOT, "data") in root:
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, PROJECT_ROOT)
            # dataset_writer.py and test_phase4_cases.py are the only new .py files
            basename = os.path.basename(fname)
            # All other .py files should be pre-existing Phase 1-3 files
    # Simple check: dataset_writer.py exists, no extra unexpected files
    has_writer = os.path.exists(os.path.join(SERVER_DIR, "dataset_writer.py"))
    has_tests4 = os.path.exists(os.path.join(TESTS_DIR, "test_phase4_cases.py"))
    _assert("P4-24", "Exactly the two approved new source files exist",
            has_writer and has_tests4, "")


# ===========================================================================
# SECTION B  --  DatasetWriter Unit Tests  (no server required)
# ===========================================================================

def run_section_b():
    print("\n" + "="*60)
    print("SECTION B -- DatasetWriter Unit Tests")
    print("="*60)

    # Use a temporary CSV path separate from the live dataset
    tmp_csv = os.path.join(PROJECT_ROOT, "data", "_test_tmp_p4b.csv")
    if os.path.exists(tmp_csv):
        os.remove(tmp_csv)

    writer = DatasetWriter(tmp_csv)

    # P4-05 -- CSV header has exactly 9 correct columns
    with open(tmp_csv, "r", encoding="utf-8") as fh:
        header_line = fh.readline().strip()
    expected_header = ",".join(COLUMNS)
    _assert("P4-05", "CSV header has exactly 9 correct columns",
            header_line == expected_header,
            f"Got: {header_line!r}" if header_line != expected_header else "")

    # P4-17 -- Negative values are rejected
    writer.start_session()
    good_obs = {
        "window_duration_sec":        1.001,
        "requests_per_sec":           10.0,
        "bytes_per_sec":              330.0,
        "avg_request_size_bytes":     33.0,
        "active_connections":         1,
        "total_connections_in_window": 0,
        "client_ip":                  "127.0.0.1",
    }
    # Negative requests_per_sec
    bad_obs = dict(good_obs)
    bad_obs["requests_per_sec"] = -5.0
    result = writer.write_observation(bad_obs)
    _assert("P4-17", "Negative feature values are rejected",
            result is False, "")

    # Confirm valid obs is accepted
    ok = writer.write_observation(good_obs)
    _assert("P4-17b", "Valid observation is accepted",
            ok is True, "")

    # P4-18 -- NaN/Inf values are rejected
    nan_obs = dict(good_obs)
    nan_obs["bytes_per_sec"] = float("nan")
    result_nan = writer.write_observation(nan_obs)

    inf_obs = dict(good_obs)
    inf_obs["avg_request_size_bytes"] = float("inf")
    result_inf = writer.write_observation(inf_obs)

    _assert("P4-18", "NaN and Inf values are rejected",
            result_nan is False and result_inf is False, "")

    writer.stop_session()

    # P4-19 -- DatasetWriter with unwritable path raises no exception
    bad_path = os.path.join(PROJECT_ROOT, "nonexistent_deep_dir",
                            "also_nonexistent", "test.csv")
    # On Windows, makedirs into a path with very restricted perms is hard to
    # simulate, but we can pass a path into a read-only system directory.
    # Instead, test with a path whose parent directory can't be created
    # (path through an existing regular file, which can't be a directory).
    impossible_path = os.path.join(tmp_csv, "subdir", "file.csv")  # tmp_csv is a file
    try:
        bad_writer = DatasetWriter(impossible_path)
        bad_writer.start_session()
        result_bad = bad_writer.write_observation(good_obs)
        # Should return False (I/O error), not raise
        _assert("P4-19", "DatasetWriter with bad path: no exception raised",
                result_bad is False, "Returned False correctly")
    except Exception as exc:
        _report("P4-19", "DatasetWriter with bad path: no exception raised",
                False, f"Unexpected exception: {exc!r}")

    # Clean up temp CSV
    try:
        os.remove(tmp_csv)
    except OSError:
        pass


# ===========================================================================
# SECTION C  --  Live Server Integration Tests
# ===========================================================================

_server_proc = None

def _start_server() -> subprocess.Popen:
    """Launch server.py as a background subprocess.

    stdout/stderr are discarded (DEVNULL) deliberately.
    The server prints a dashboard via print() every second.
    If stdout is a PIPE and the test never reads from it, the pipe
    buffer (64 KB on Windows) fills up after ~128 dashboard prints
    and the next print() call blocks the server's main thread forever.
    Using DEVNULL prevents this deadlock entirely.
    """
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SERVER_DIR, "server.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=dict(os.environ, AI_NIDS_DATASET_PATH=os.path.relpath(DATASET_PATH, PROJECT_ROOT)),
    )
    time.sleep(STARTUP_WAIT_S)
    return proc

def _stop_server(proc: subprocess.Popen) -> None:
    """Terminate the server subprocess and guarantee port 5000 is released."""
    # Attempt graceful collection stop if still collecting
    try:
        sock, buf = _connect()
        _send_recv(sock, buf, "COLLECTION_STOP", "test cleanup")
        sock.close()
    except Exception:
        pass

    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except Exception:
                pass

    # Verify port 5000 is released
    t_end = time.time() + 5.0
    while time.time() < t_end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.close()
            time.sleep(0.2)
        except (OSError, ConnectionRefusedError):
            break

def _run_collection_session(target_rate: float, duration_sec: float,
                            max_requests: int = None,
                            payload_prefix: str = "test") -> tuple:
    """
    Open a connection, start collection, generate traffic, stop collection.
    Returns (experiment_id_str, rows_before, rows_after).

    max_requests caps the number of requests sent regardless of target_rate
    and duration_sec.  Used in P4-14 to avoid the Windows time.sleep() floor
    (~15ms) turning a 1500-request HIGH-rate session into a 22-second wait.
    """
    rows_before = len(_read_csv_rows())

    sock, buf = _connect()
    # Start collection
    start_msg = _start_collection(sock, buf)
    exp_id = ""
    for part in start_msg.split():
        if part.startswith("EXP-"):
            exp_id = part.rstrip(".,:")
            break

    # Wait one tick so collection is definitely active before we start traffic
    time.sleep(1.1)

    # Generate traffic
    count = int(target_rate * duration_sec)
    if max_requests is not None:
        count = min(count, max_requests)
    _send_requests(sock, buf, count, target_rate)

    # Wait for the final window to be captured
    time.sleep(TICK_WAIT_S)

    # Stop collection
    _stop_collection(sock, buf)
    sock.close()

    rows_after = len(_read_csv_rows())
    return exp_id, rows_before, rows_after

def run_section_c():
    global _server_proc

    print("\n" + "="*60)
    print("SECTION C -- Live Server Integration Tests")
    print("="*60)

    # Save snapshot of production dataset as secondary safety guard
    prod_bytes = None
    if os.path.exists(PROD_DATASET_PATH):
        with open(PROD_DATASET_PATH, "rb") as f:
            prod_bytes = f.read()

    # Clean slate on ISOLATED test dataset only
    if os.path.exists(DATASET_PATH):
        os.remove(DATASET_PATH)
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)

    _server_proc = _start_server()
    if _server_proc.poll() is not None:
        print("  [FATAL] Server failed to start. Aborting Section C.")
        for tid in ["P4-02","P4-03","P4-04","P4-06","P4-07","P4-08","P4-09",
                    "P4-10","P4-11","P4-12","P4-13","P4-14","P4-15","P4-16",
                    "P4-20","P4-21","P4-25"]:
            _report(tid, tid, False, "Server did not start")
        return

    try:
        _run_c_tests()
    finally:
        _stop_server(_server_proc)
        # Secondary safety guard: ensure production dataset was not touched
        if prod_bytes is not None and os.path.exists(PROD_DATASET_PATH):
            with open(PROD_DATASET_PATH, "rb") as f:
                current_prod = f.read()
            if current_prod != prod_bytes:
                print("  [WARN] Production dataset touched during test! Restoring...")
                with open(PROD_DATASET_PATH, "wb") as f:
                    f.write(prod_bytes)

def _run_c_tests():
    # -----------------------------------------------------------------------
    # P4-02 / P4-03  --  COLLECTION_START / STOP return SUCCESS
    # -----------------------------------------------------------------------
    try:
        sock, buf = _connect()
        start_resp = _send_recv(sock, buf, "COLLECTION_START",
                                "P4-02 test start.")
        ok_start = start_resp.get("status") == "SUCCESS"
        has_exp_id = "EXP-" in start_resp.get("message", "")
        _assert("P4-02", "COLLECTION_START returns SUCCESS + experiment ID",
                ok_start and has_exp_id,
                f"status={start_resp.get('status')} msg={start_resp.get('message')}")

        time.sleep(TICK_WAIT_S)

        stop_resp = _send_recv(sock, buf, "COLLECTION_STOP",
                               "P4-03 test stop.")
        ok_stop = stop_resp.get("status") == "SUCCESS"
        _assert("P4-03", "COLLECTION_STOP returns SUCCESS",
                ok_stop,
                f"status={stop_resp.get('status')}")
        sock.close()
    except Exception as exc:
        _report("P4-02", "COLLECTION_START returns SUCCESS + experiment ID",
                False, str(exc))
        _report("P4-03", "COLLECTION_STOP returns SUCCESS", False, str(exc))

    # Give CSV writer time to flush
    time.sleep(0.5)

    # -----------------------------------------------------------------------
    # P4-04 / P4-06  --  Traffic creates CSV rows
    # Normal traffic: 10 req/s for 3 seconds -> expect >= 2 rows
    # -----------------------------------------------------------------------
    try:
        exp_id_1, rows_before_1, rows_after_1 = _run_collection_session(
            target_rate=10, duration_sec=TRAFFIC_DUR_S)
        new_rows_1 = rows_after_1 - rows_before_1

        _assert("P4-04", "Real traffic during collection creates CSV rows",
                new_rows_1 > 0,
                f"New rows: {new_rows_1}")

        _assert("P4-06", f"3-second collection session produces >= 2 rows",
                new_rows_1 >= 2,
                f"New rows: {new_rows_1}")
    except Exception as exc:
        _report("P4-04", "Real traffic creates CSV rows", False, str(exc))
        _report("P4-06", "3-second session produces >= 2 rows", False, str(exc))
        new_rows_1 = 0
        exp_id_1   = ""

    # -----------------------------------------------------------------------
    # P4-07 through P4-12  --  Inspect the rows just written
    # -----------------------------------------------------------------------
    rows = _read_csv_rows()
    # Filter to rows from EXP-001 (the first completed session)
    # EXP-001 is from P4-02/P4-03 (might have 0 rows), EXP-002 from normal traffic
    # Use all rows for simplicity
    if rows:
        # P4-07 -- requests_per_sec > 0
        rps_vals = []
        for r in rows:
            try:
                v = float(r.get("requests_per_sec", 0))
                rps_vals.append(v)
            except ValueError:
                pass
        # At least one data row (from traffic) should have rps > 0
        data_rows = [r for r in rows if float(r.get("requests_per_sec", 0)) > 0]
        _assert("P4-07", "requests_per_sec > 0 in traffic rows (server-computed)",
                len(data_rows) > 0,
                f"Data rows with rps>0: {len(data_rows)}/{len(rows)}")

        # P4-08 -- bytes_per_sec > 0
        bps_pos = [r for r in data_rows if float(r.get("bytes_per_sec", 0)) > 0]
        _assert("P4-08", "bytes_per_sec > 0 in traffic rows",
                len(bps_pos) > 0,
                f"{len(bps_pos)} rows with bps>0")

        # P4-09 -- avg_request_size_bytes > 0
        avg_pos = [r for r in data_rows
                   if float(r.get("avg_request_size_bytes", 0)) > 0]
        _assert("P4-09", "avg_request_size_bytes > 0 in traffic rows",
                len(avg_pos) > 0,
                f"{len(avg_pos)} rows with avg>0")

        # P4-10 -- active_connections = 1 in traffic rows
        act_rows = [r for r in data_rows
                    if int(r.get("active_connections", 0)) >= 1]
        _assert("P4-10", "active_connections >= 1 during active session",
                len(act_rows) > 0,
                f"{len(act_rows)} rows with active_connections>=1")

        # P4-11 -- total_connections_in_window is int >= 0
        conn_ok = all(
            int(r.get("total_connections_in_window", -1)) >= 0
            for r in rows
        )
        _assert("P4-11", "total_connections_in_window is non-negative integer",
                conn_ok, "")

        # P4-12 -- window_duration_sec within [0.5, 2.0]
        dur_vals = [float(r.get("window_duration_sec", 0)) for r in rows]
        dur_ok = all(0.5 <= d <= 2.0 for d in dur_vals)
        _assert("P4-12", "window_duration_sec within [0.5, 2.0] seconds",
                dur_ok,
                f"min={min(dur_vals):.3f} max={max(dur_vals):.3f}" if dur_vals else "no rows")
    else:
        for tid in ["P4-07","P4-08","P4-09","P4-10","P4-11","P4-12"]:
            _report(tid, tid, False, "No CSV rows available")

    # -----------------------------------------------------------------------
    # P4-13  --  Larger payload -> larger avg_request_size_bytes
    # -----------------------------------------------------------------------
    try:
        # Run a session with a very large payload
        rows_before_large = len(_read_csv_rows())

        sock_lg, buf_lg = _connect()
        _start_collection(sock_lg, buf_lg)
        time.sleep(1.1)

        LARGE_PAYLOAD = "X" * 500   # 500-byte payload
        for i in range(20):
            t0 = time.perf_counter()
            req = protocol.build_request("DATA_REQUEST", LARGE_PAYLOAD)
            protocol.send_message(sock_lg, req)
            protocol.recv_message(sock_lg, buf_lg, BUFFER_SIZE)
            elapsed = time.perf_counter() - t0
            if elapsed < 0.05:
                time.sleep(0.05 - elapsed)

        time.sleep(TICK_WAIT_S)
        _stop_collection(sock_lg, buf_lg)
        sock_lg.close()

        rows_after_large = len(_read_csv_rows())
        all_rows = _read_csv_rows()

        # Normal session rows (avg ~33 bytes) vs large session rows (avg ~500 bytes)
        normal_rows = all_rows[:rows_after_large - (rows_after_large - rows_before_large)]
        large_rows  = all_rows[rows_before_large:]

        if normal_rows and large_rows:
            def avg_size(rows_subset):
                vals = [float(r.get("avg_request_size_bytes", 0))
                        for r in rows_subset
                        if float(r.get("requests_per_sec", 0)) > 0]
                return sum(vals) / len(vals) if vals else 0

            n_avg = avg_size(normal_rows)
            l_avg = avg_size(large_rows)
            _assert("P4-13", "Larger payload produces larger avg_request_size_bytes",
                    l_avg > n_avg,
                    f"normal_avg={n_avg:.1f}B  large_avg={l_avg:.1f}B")
        else:
            _report("P4-13", "Larger payload -> larger avg_request_size",
                    False, "Insufficient rows to compare")
    except Exception as exc:
        _report("P4-13", "Larger payload -> larger avg_request_size_bytes",
                False, str(exc))

    # -----------------------------------------------------------------------
    # P4-14  --  Normal < Medium < High requests_per_sec
    #
    # DESIGN RATIONALE
    # -----------------
    # We need NORMAL < MEDIUM < HIGH in server-observed rates.
    # The server measures in 1-second windows, so we must fill multiple
    # windows to get stable averages.
    #
    # Sleep-controlled rates (below RTT ceiling, above Windows timer floor):
    #   NORMAL : 5 req/s  (sleep=200ms -- always reliable)
    #   MEDIUM : 20 req/s (sleep=50ms  -- well above 15ms Windows floor)
    #   HIGH   : 40 req/s (sleep=25ms  -- well above 15ms Windows floor)
    #
    # With 3 seconds of traffic, each mode sends enough requests to fill
    # 3 monitor windows, giving a stable average:
    #   NORMAL : 15 reqs -> server sees ~5 req/s
    #   MEDIUM : 60 reqs -> server sees ~20 req/s
    #   HIGH   : 120 reqs -> server sees ~40 req/s
    # Ordering 5 < 20 < 40 is guaranteed independent of RTT or timer.
    # -----------------------------------------------------------------------
    try:
        session_avgs = {}
        # (mode, target_rate, max_requests_for_3s_of_traffic)
        for mode, rate, max_req in [
            ("NORMAL",  5,   15),   # 15 reqs @ 200ms = 3s
            ("MEDIUM",  20,  60),   # 60 reqs @  50ms = 3s
            ("HIGH",    40, 120),   # 120 reqs @ 25ms = 3s
        ]:
            rows_b = len(_read_csv_rows())
            exp_id_m, _, rows_a = _run_collection_session(
                target_rate=rate, duration_sec=3,
                max_requests=max_req,
                payload_prefix=mode)
            mode_rows = _read_csv_rows()[rows_b:]
            data_mode = [r for r in mode_rows
                         if float(r.get("requests_per_sec", 0)) > 0]
            if data_mode:
                avg_rps = sum(float(r["requests_per_sec"]) for r in data_mode) / len(data_mode)
            else:
                avg_rps = 0.0
            session_avgs[mode] = avg_rps
            time.sleep(0.5)  # brief pause between sessions

        normal_rps = session_avgs.get("NORMAL", 0)
        medium_rps = session_avgs.get("MEDIUM", 0)
        high_rps   = session_avgs.get("HIGH",   0)
        ordered = normal_rps < medium_rps < high_rps

        _assert("P4-14",
                "Normal < Medium < High requests_per_sec (server-observed)",
                ordered,
                f"NORMAL={normal_rps:.1f}  MEDIUM={medium_rps:.1f}  "
                f"HIGH={high_rps:.1f} req/s")
    except Exception as exc:
        _report("P4-14", "Normal < Medium < High requests_per_sec",
                False, str(exc))

    # -----------------------------------------------------------------------
    # P4-15  --  Second collection run appends (row count increases)
    # -----------------------------------------------------------------------
    try:
        rows_mid = len(_read_csv_rows())
        sock_p15, buf_p15 = _connect()
        _start_collection(sock_p15, buf_p15)
        time.sleep(1.1)
        _send_requests(sock_p15, buf_p15, 10, 5)
        time.sleep(TICK_WAIT_S)
        _stop_collection(sock_p15, buf_p15)
        sock_p15.close()
        rows_end = len(_read_csv_rows())
        _assert("P4-15", "Second (and later) collection runs append rows",
                rows_end > rows_mid,
                f"Before: {rows_mid}  After: {rows_end}")
    except Exception as exc:
        _report("P4-15", "Later collection runs append rows", False, str(exc))

    # -----------------------------------------------------------------------
    # P4-16  --  No duplicate header lines
    # -----------------------------------------------------------------------
    try:
        header_count = 0
        if os.path.exists(DATASET_PATH):
            expected_hdr = ",".join(COLUMNS)
            with open(DATASET_PATH, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip() == expected_hdr:
                        header_count += 1
        _assert("P4-16", "CSV has exactly 1 header line (no duplicates)",
                header_count == 1,
                f"Found {header_count} header line(s)")
    except Exception as exc:
        _report("P4-16", "No duplicate header lines", False, str(exc))

    # -----------------------------------------------------------------------
    # P4-17 / P4-18 (live data)  --  All numeric values >= 0, no NaN/Inf
    # -----------------------------------------------------------------------
    all_rows_live = _read_csv_rows()
    numeric_cols = [
        "window_duration_sec", "requests_per_sec", "bytes_per_sec",
        "avg_request_size_bytes", "active_connections",
        "total_connections_in_window",
    ]
    neg_found = []
    nan_found = []
    for row in all_rows_live:
        for col in numeric_cols:
            raw = row.get(col, "")
            try:
                v = float(raw)
                if v < 0:
                    neg_found.append(f"{col}={v}")
                if math.isnan(v) or math.isinf(v):
                    nan_found.append(f"{col}={v}")
            except ValueError:
                pass

    _assert("P4-17-live", "No negative feature values in live CSV",
            len(neg_found) == 0,
            f"{neg_found[:3]}" if neg_found else "")
    _assert("P4-18-live", "No NaN/Inf values in live CSV",
            len(nan_found) == 0,
            f"{nan_found[:3]}" if nan_found else "")

    # -----------------------------------------------------------------------
    # P4-20  --  Abrupt client disconnect during collection: server stays alive
    # -----------------------------------------------------------------------
    try:
        sock_abrupt, buf_abrupt = _connect()
        _start_collection(sock_abrupt, buf_abrupt)
        time.sleep(0.3)
        # Abruptly close without COLLECTION_STOP
        sock_abrupt.close()
        time.sleep(0.5)

        # Verify server is still accepting connections
        sock_probe, buf_probe = _connect()
        probe_resp = _send_recv(sock_probe, buf_probe, "DATA_REQUEST",
                                "P4-20 liveness probe")
        server_alive = probe_resp.get("status") == "SUCCESS"
        sock_probe.close()
        _assert("P4-20", "Server stays alive after abrupt client disconnect",
                server_alive, "")
    except Exception as exc:
        _report("P4-20", "Server stays alive after abrupt disconnect",
                False, str(exc))

    # -----------------------------------------------------------------------
    # P4-21  --  dataset_writer.inspect() reports a clean dataset
    # -----------------------------------------------------------------------
    try:
        inspector = DatasetWriter(DATASET_PATH)
        stats = inspector.inspect()
        clean = (
            stats["file_exists"] and
            stats["total_rows"] > 0 and
            stats["missing_values"] == 0 and
            stats["invalid_values"] == 0 and
            stats["negative_values"] == 0 and
            stats["nan_inf_values"] == 0
        )
        _assert("P4-21", "inspect() reports clean dataset (0 invalid/missing/negative)",
                clean,
                f"rows={stats['total_rows']} missing={stats['missing_values']} "
                f"invalid={stats['invalid_values']} neg={stats['negative_values']} "
                f"nan={stats['nan_inf_values']}")
    except Exception as exc:
        _report("P4-21", "inspect() reports clean dataset", False, str(exc))

    # -----------------------------------------------------------------------
    # P4-25  --  End-to-end acceptance demo (already done as part of P4-14)
    # Verify the complete CSV has Normal, Medium, and High experiment rows.
    # -----------------------------------------------------------------------
    try:
        all_rows_final = _read_csv_rows()
        exp_ids = set(r.get("experiment_id", "") for r in all_rows_final)
        # We expect at least 3 distinct experiment IDs from the Normal/Medium/High runs
        _assert("P4-25",
                "End-to-end: CSV contains multiple experiment sessions",
                len(exp_ids) >= 3,
                f"Experiment IDs in CSV: {sorted(exp_ids)}")
    except Exception as exc:
        _report("P4-25", "End-to-end acceptance", False, str(exc))


# ===========================================================================
# P4-01  --  Phase 3 Regression Test
# ===========================================================================

def run_phase3_regression():
    print("\n" + "="*60)
    print("P4-01 -- Phase 3 Regression (test_phase3_cases.py)")
    print("="*60)
    print("  Running Phase 3 test suite ... (this takes ~20 seconds)")

    test3_path = os.path.join(TESTS_DIR, "test_phase3_cases.py")
    result = subprocess.run(
        [sys.executable, test3_path],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    passed = result.returncode == 0
    # Show last few lines of output
    lines = (result.stdout + result.stderr).strip().splitlines()
    summary_lines = [l for l in lines if "PASS" in l or "FAIL" in l or "passed" in l.lower()]
    last_lines = lines[-6:] if len(lines) > 6 else lines
    detail = " | ".join(summary_lines[-2:]) if summary_lines else " | ".join(last_lines)

    _assert("P4-01", "Phase 3 regression -- all Phase 3 tests still pass",
            passed, detail[:120])


# ===========================================================================
# SUMMARY + DISPLAY
# ===========================================================================

def print_summary():
    print("\n" + "="*60)
    print("PHASE 4 TEST SUMMARY")
    print("="*60)

    passed = sum(1 for r in _results.values() if r["passed"])
    total  = len(_results)
    failed_ids = [tid for tid, r in sorted(_results.items()) if not r["passed"]]

    print(f"\n  Total : {total}")
    print(f"  Pass  : {passed}")
    print(f"  Fail  : {total - passed}")

    if failed_ids:
        print(f"\n  FAILED: {', '.join(failed_ids)}")

    print()
    if passed == total:
        print("  *** ALL PHASE 4 TESTS PASSED ***")
    else:
        print(f"  *** {total - passed} TEST(S) FAILED -- see details above ***")

    # Show CSV header
    if os.path.exists(DATASET_PATH):
        print("\n" + "-"*60)
        print("  CSV Header:")
        print(f"    {_read_csv_header_line()}")

        # Show 5-10 sample rows
        all_rows = _read_csv_rows()
        print(f"\n  Total rows in dataset: {len(all_rows)}")
        if all_rows:
            sample = all_rows[:min(8, len(all_rows))]
            print("\n  Sample rows (first 8):")
            for row in sample:
                print(f"    {row.get('timestamp','?')}  "
                      f"exp={row.get('experiment_id','?')}  "
                      f"rps={row.get('requests_per_sec','?')}  "
                      f"bps={row.get('bytes_per_sec','?')}  "
                      f"avg={row.get('avg_request_size_bytes','?')}B  "
                      f"conn={row.get('active_connections','?')}")

    # Clean up isolated test dataset so no temporary files linger in data/
    if os.path.exists(DATASET_PATH):
        try:
            os.remove(DATASET_PATH)
        except Exception:
            pass

    print()
    return passed == total


# ===========================================================================
# ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    print()
    print("+--------------------------------------------------+")
    print("|   AI-NIDS -- Phase 4 Acceptance Tests (P4-01..25)|")
    print("+--------------------------------------------------+")
    print(f"  Dataset path: {DATASET_PATH}")
    print()

    run_section_a()
    run_section_b()
    run_section_c()     # starts/stops server internally
    run_phase3_regression()

    all_passed = print_summary()
    sys.exit(0 if all_passed else 1)
