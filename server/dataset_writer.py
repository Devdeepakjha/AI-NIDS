"""
=============================================================================
server/dataset_writer.py  --  CSV Dataset Writer  (Phase 4)
=============================================================================

PROJECT : AI-Based Network Intrusion Detection System
PHASE   : 4 -- Network Feature Extraction & Dataset Generation
IMPORTED BY : server/monitor.py  (called from the background display thread)

PURPOSE
-------
Write validated per-window traffic observations to a CSV dataset file.

Every row corresponds to one 1-second observation window during which the
server was actively measuring incoming TCP traffic.  All numeric values come
from the server's own counters -- no client-reported figures are used except
the client IP address (taken directly from the accepted socket).

DESIGN PRINCIPLES
-----------------
1.  Standard library only.  No pandas, numpy, or third-party packages.
    The csv module handles streaming row-by-row writes cleanly.
2.  Thread-safe.  All public methods are protected by self._lock.
3.  Fail-safe.  I/O errors never propagate to the caller.  They are logged
    and skipped.  The TCP server must never crash because the CSV cannot
    be written.
4.  Idempotent header.  The CSV header is written once at construction.
    Subsequent collection runs that append to the same file never re-write
    the header.
5.  Minimal.  Feature extraction is simple arithmetic on existing counters
    already maintained by TrafficMonitor.  No separate computation layer.

CSV SCHEMA (9 columns)
-----------------------
Column                     Category      ML candidate?
-----------------------------------------------------------
timestamp                  Identifier    NO  -- time reference only
experiment_id              Metadata      NO  -- collection-run label only
window_duration_sec        Timing meta   NO  -- normalisation context
requests_per_sec           Feature       YES
bytes_per_sec              Feature       YES
avg_request_size_bytes     Feature       YES
active_connections         Feature       YES
total_connections_in_window Feature      YES
client_ip                  Identifier    NO  -- encode before using in ML

DATA LEAKAGE GUARD
------------------
The schema deliberately excludes:
  - traffic_mode    (experiment control, not observed behaviour)
  - target_rate     (experiment control, not observed behaviour)

CN CONCEPTS COVERED
-------------------
  Application-layer data collection  -- measuring our own protocol only
  CSV streaming                      -- incremental writes, no accumulation
  Row validation                     -- type/range checks before persisting

VIVA TIPS
---------
  Q: Why not pandas?
  A: csv.DictWriter from the standard library handles streaming row-by-row
     appends with no overhead.  pandas is optimised for in-memory batch
     analysis, not incremental server-side writes.  Using it at runtime
     would add an unnecessary dependency with no benefit.

  Q: How is data leakage prevented?
  A: traffic_mode and target_rate never appear in the schema.
     experiment_id is present as metadata and is explicitly labelled as
     non-ML.  Phase 5 will select only the five Feature columns.
=============================================================================
"""

import csv
import math
import os
import threading
from datetime import datetime


# ---------------------------------------------------------------------------
# CSV schema -- single source of truth for column names and order.
#
# Changing this list changes the file format for all existing and future runs.
# Do NOT reorder without deleting all existing CSV data.
# ---------------------------------------------------------------------------
COLUMNS = [
    "timestamp",                    # Identifier  -- wall-clock time at window end
    "experiment_id",                # Metadata    -- collection run label (EXP-NNN)
    "window_duration_sec",          # Timing meta -- actual elapsed seconds this window
    "requests_per_sec",             # Feature     -- server-observed request rate
    "bytes_per_sec",                # Feature     -- server-observed app-payload byte rate
    "avg_request_size_bytes",       # Feature     -- mean app-level payload size per request
    "active_connections",           # Feature     -- live TCP connections at window end
    "total_connections_in_window",  # Feature     -- new connections accepted this window
    "client_ip",                    # Identifier  -- last-seen client IP address
]


class DatasetWriter:
    """
    Manages the lifecycle of the network traffic CSV dataset.

    Usage
    -----
        writer = DatasetWriter("data/network_traffic.csv")
        exp_id = writer.start_session()          # "EXP-001"
        writer.write_observation({...})          # called once per 1-s window
        writer.stop_session()

    All methods are thread-safe.  I/O failures are caught and logged;
    they never propagate to the caller.
    """

    def __init__(self, filepath: str) -> None:
        """
        Parameters
        ----------
        filepath : str
            Path to the CSV file.  Parent directories are created if absent.
        """
        self._filepath = filepath
        self._lock     = threading.Lock()

        self._rows_written: int = 0
        self._exp_counter:  int = 0
        self._current_experiment_id: str = ""
        self._active: bool = False

        # Prepare filesystem -- errors are logged, not raised
        self._ensure_data_dir()
        self._ensure_header()

    # ------------------------------------------------------------------
    # Session control
    # ------------------------------------------------------------------

    def start_session(self) -> str:
        """
        Begin a new dataset collection session.

        Increments the experiment counter, assigns the next experiment ID,
        and marks collection as active.

        Returns
        -------
        str
            The new experiment ID (e.g. "EXP-001").
        """
        with self._lock:
            self._exp_counter += 1
            self._current_experiment_id = f"EXP-{self._exp_counter:03d}"
            self._active = True
            return self._current_experiment_id

    def stop_session(self) -> None:
        """
        End the current collection session.
        Idempotent -- safe to call even if no session is active.
        """
        with self._lock:
            self._active = False

    # ------------------------------------------------------------------
    # Properties (thread-safe read access)
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        """True while a collection session is in progress."""
        with self._lock:
            return self._active

    @property
    def current_experiment_id(self) -> str:
        """Current experiment ID, or empty string if not collecting."""
        with self._lock:
            return self._current_experiment_id

    @property
    def rows_written(self) -> int:
        """Total rows successfully written since this writer was created."""
        with self._lock:
            return self._rows_written

    # ------------------------------------------------------------------
    # Observation writing
    # ------------------------------------------------------------------

    def write_observation(self, obs: dict) -> bool:
        """
        Validate and append one observation row to the CSV.

        This method adds 'timestamp' (wall-clock at call time) and
        'experiment_id' (current session) to the caller-supplied dict.

        Parameters
        ----------
        obs : dict
            Must contain all COLUMNS keys except 'timestamp' and
            'experiment_id', which are supplied here.

        Returns
        -------
        bool
            True  -- row written successfully.
            False -- skipped (not active, validation failure, or I/O error).

        Thread-safety note
        ------------------
        The lock is held ONLY for brief state reads/writes (Phases 1 and 4).
        File I/O happens in Phase 3 WITHOUT the lock to prevent blocking
        callers (e.g. handle_client calling start_session()) while a slow
        file write is in progress (e.g. OneDrive sync intercepting the open).
        This is safe because write_observation() is called exclusively from
        the monitor background thread -- there are never concurrent writes.
        """
        # --- Phase 1: check active state, capture session ID (under lock, fast) ---
        with self._lock:
            if not self._active:
                return False
            row = dict(obs)
            row["timestamp"]     = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
            row["experiment_id"] = self._current_experiment_id

        # --- Phase 2: validate (no lock needed -- row is a local copy) ---
        valid, reason = self._validate(row)
        if not valid:
            print(f"[DATASET] WARN: Skipped invalid observation -- {reason}")
            return False

        # --- Phase 3: write to file (NO LOCK during I/O) ---
        # Only the monitor background thread calls this method, so there is
        # never a concurrent write.  The lock does not need to cover I/O.
        try:
            with open(self._filepath, "a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=COLUMNS)
                writer.writerow(row)
        except OSError as exc:
            print(f"[DATASET] ERROR: Could not write observation -- {exc}")
            return False

        # --- Phase 4: update row counter (under lock, fast) ---
        with self._lock:
            self._rows_written += 1
        return True

    # ------------------------------------------------------------------
    # Dataset inspection (used by P4-21 validation test)
    # ------------------------------------------------------------------

    def inspect(self) -> dict:
        """
        Read the CSV and return a summary statistics dict.

        Uses csv.DictReader from the standard library.  No pandas.

        Returns an empty result dict if the file does not exist.
        """
        result = {
            "filepath":        self._filepath,
            "file_exists":     False,
            "total_rows":      0,
            "total_columns":   len(COLUMNS),
            "columns":         list(COLUMNS),
            "missing_values":  0,
            "invalid_values":  0,
            "negative_values": 0,
            "nan_inf_values":  0,
            "duplicate_rows":  0,
            "numeric_stats":   {},
        }

        if not os.path.exists(self._filepath):
            return result

        result["file_exists"] = True

        rows = []
        try:
            with open(self._filepath, "r", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    rows.append(row)
        except OSError as exc:
            print(f"[DATASET] ERROR: Cannot read CSV for inspection -- {exc}")
            return result

        result["total_rows"] = len(rows)

        # Missing / empty values
        for row in rows:
            for col in COLUMNS:
                if col not in row or row[col] is None or str(row[col]).strip() == "":
                    result["missing_values"] += 1

        # Numeric statistics and validity
        numeric_cols = [
            "window_duration_sec",
            "requests_per_sec",
            "bytes_per_sec",
            "avg_request_size_bytes",
            "active_connections",
            "total_connections_in_window",
        ]
        for col in numeric_cols:
            values = []
            for row in rows:
                raw = row.get(col, "")
                try:
                    v = float(raw)
                    if math.isnan(v) or math.isinf(v):
                        result["nan_inf_values"] += 1
                    elif v < 0:
                        result["negative_values"] += 1
                    else:
                        values.append(v)
                except (TypeError, ValueError):
                    result["invalid_values"] += 1

            if values:
                result["numeric_stats"][col] = {
                    "min":  round(min(values),            4),
                    "max":  round(max(values),            4),
                    "mean": round(sum(values) / len(values), 4),
                }

        # Duplicate rows (full-row comparison)
        seen = set()
        for row in rows:
            key = tuple(row.get(c, "") for c in COLUMNS)
            if key in seen:
                result["duplicate_rows"] += 1
            seen.add(key)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_data_dir(self) -> None:
        """Create the parent directory of the CSV file if it does not exist."""
        directory = os.path.dirname(os.path.abspath(self._filepath))
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            print(f"[DATASET] ERROR: Cannot create data directory '{directory}' -- {exc}")

    def _ensure_header(self) -> None:
        """
        Write the CSV header if the file does not exist or is empty.
        Preserves existing header on subsequent runs (no duplication).
        """
        try:
            if os.path.exists(self._filepath) and os.path.getsize(self._filepath) > 0:
                return  # Header already present
            with open(self._filepath, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=COLUMNS)
                writer.writeheader()
        except OSError as exc:
            print(f"[DATASET] ERROR: Cannot write CSV header -- {exc}")

    @staticmethod
    def _validate(row: dict) -> tuple:
        """
        Validate a row dict before writing.

        Returns
        -------
        (True, "")           -- row is valid
        (False, reason_str)  -- row is invalid; caller should skip it
        """
        # All columns must be present
        for col in COLUMNS:
            if col not in row:
                return False, f"Missing column '{col}'"

        # Numeric columns: must be finite and non-negative
        numeric_nonneg = [
            "window_duration_sec",
            "requests_per_sec",
            "bytes_per_sec",
            "avg_request_size_bytes",
            "active_connections",
            "total_connections_in_window",
        ]
        for col in numeric_nonneg:
            val = row[col]
            try:
                fval = float(val)
            except (TypeError, ValueError):
                return False, f"'{col}' is not numeric: {val!r}"
            if math.isnan(fval):
                return False, f"'{col}' is NaN"
            if math.isinf(fval):
                return False, f"'{col}' is Inf"
            if fval < 0:
                return False, f"'{col}' is negative: {fval}"

        # window_duration_sec must be strictly positive (window must have existed)
        if float(row["window_duration_sec"]) <= 0:
            return False, "window_duration_sec must be > 0"

        # String identifier columns must be non-empty
        for col in ("timestamp", "experiment_id", "client_ip"):
            if not str(row.get(col, "")).strip():
                return False, f"'{col}' is empty"

        return True, ""
