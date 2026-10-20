"""
=============================================================================
server/monitor.py  --  Traffic Monitor  (Phase 4)
=============================================================================

PROJECT : AI-Based Network Intrusion Detection System
PHASE   : 4 -- Network Feature Extraction & Dataset Generation
IMPORTED BY : server/server.py

WHAT THIS MODULE DOES
---------------------
Measures, aggregates, and displays real-time TCP traffic statistics.
In Phase 4 it also feeds per-window observations to the DatasetWriter.

PHASE 3 FUNCTIONALITY (unchanged)
----------------------------------
  - Background daemon thread wakes every MONITOR_INTERVAL seconds
  - Computes per-interval request rate and byte rate from cumulative counters
  - Prints a live dashboard to the server terminal
  - get_snapshot() returns a dict for external callers

PHASE 4 ADDITIONS
-----------------
  - DatasetWriter integration: after each interval, if a collection session
    is active, write one CSV row with the window's aggregate metrics.
  - Per-window connection counter: total_connections_in_window
  - Per-window IP tracking: last_client_ip seen in the window
  - Actual window duration: recorded by _compute_interval_metrics()
  - get_snapshot() includes the three new fields above

THREADING MODEL
---------------
  - TrafficMonitor uses ONE lock (self._lock) to protect all counters.
  - The display thread (self._display_thread) is the ONLY writer of the
    interval-derived fields (_last_window_duration, _last_window_connections).
    After _compute_interval_metrics() returns, the display thread reads these
    inside the same lock block -- no race condition.
  - DatasetWriter has its own independent lock.  The two locks are NEVER held
    simultaneously from the same thread, so no deadlock is possible.

CN CONCEPTS COVERED (Phase 4 additions)
-----------------------------------------
  Time-windowed measurement    -- fixed 1-second observation windows
  Feature extraction           -- deriving meaningful metrics from counters
  Dataset construction         -- streaming CSV writes from live measurements
  Thread safety                -- lock discipline across two independent locks
=============================================================================
"""

import os
import time
import threading
from datetime import datetime


class TrafficMonitor:
    """
    Real-time traffic monitor with optional Phase 4 dataset collection.

    Parameters
    ----------
    interval : float
        Dashboard refresh interval in seconds (must match COLLECTION_WINDOW_SEC).
    dataset_writer : DatasetWriter or None
        Phase 4 dataset writer.  If None, Phase 3 behaviour only.
    """

    def __init__(self, interval: float = 1.0, dataset_writer=None) -> None:

        self._lock            = threading.Lock()
        self._interval        = interval
        self._dataset_writer  = dataset_writer   # Phase 4: optional DatasetWriter

        # ------------------------------------------------------------------
        # Cumulative totals -- never reset after start()
        # ------------------------------------------------------------------
        self.total_requests:    int = 0
        self.total_bytes:       int = 0
        self.total_connections: int = 0
        self.active_connections: int = 0

        # ------------------------------------------------------------------
        # Per-interval counters -- reset by _compute_interval_metrics()
        # ------------------------------------------------------------------
        self._interval_requests: int   = 0
        self._interval_bytes:    int   = 0
        self._interval_start:    float = time.perf_counter()

        # ------------------------------------------------------------------
        # Computed rates -- updated by _compute_interval_metrics()
        # ------------------------------------------------------------------
        self.requests_per_sec: float = 0.0
        self.bytes_per_sec:    float = 0.0

        # ------------------------------------------------------------------
        # Phase 4: per-window tracking fields
        # ------------------------------------------------------------------
        # _window_connections   : new connections accepted in the current window
        #                         (reset each interval by _compute_interval_metrics)
        # _last_window_connections : saved value of the previous window
        # _last_window_duration    : actual elapsed seconds of the last window
        # _last_client_ip          : most recently seen client IP address
        # ------------------------------------------------------------------
        self._window_connections:      int   = 0
        self._last_window_connections: int   = 0
        self._last_window_duration:    float = 0.0
        self._last_client_ip:          str   = "0.0.0.0"

        # ------------------------------------------------------------------
        # Display thread
        # ------------------------------------------------------------------
        self._running: bool = False
        self._display_thread = threading.Thread(
            target=self._display_loop,
            daemon=True,
            name="TrafficMonitor-Display",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background display thread and reset the interval timer."""
        self._running       = True
        self._interval_start = time.perf_counter()
        self._display_thread.start()

    def stop(self) -> None:
        """Signal the display thread to stop (it exits on the next wake-up)."""
        self._running = False

    # ------------------------------------------------------------------
    # Event hooks (called from handle_client in server.py)
    # ------------------------------------------------------------------

    def record_connect(self, client_ip: str) -> None:
        """
        Record a new client connection.
        Increments active_connections, total_connections, and the per-window
        connection counter.  Updates last-seen client IP.
        """
        with self._lock:
            self.total_connections    += 1
            self.active_connections   += 1
            self._window_connections  += 1      # Phase 4: per-window counter
            self._last_client_ip       = client_ip  # Phase 4: IP tracking

    def record_disconnect(self, client_ip: str) -> None:
        """Decrement the active connection count.  Never goes below zero."""
        with self._lock:
            self.active_connections = max(0, self.active_connections - 1)

    def record_request(self, client_ip: str, payload_size: int) -> None:
        """
        Record one valid DATA_REQUEST / STATUS_REQUEST.
        Called ONLY for normal traffic requests -- NOT for COLLECTION_START/STOP.

        Parameters
        ----------
        client_ip : str
            Source IP address (from the socket).
        payload_size : int
            Application-level UTF-8 payload size in bytes.
            This is NOT the TCP segment size or IP packet size.
        """
        with self._lock:
            self.total_requests      += 1
            self.total_bytes         += payload_size
            self._interval_requests  += 1
            self._interval_bytes     += payload_size
            self._last_client_ip      = client_ip   # Phase 4: update per request

    # ------------------------------------------------------------------
    # Snapshot (public API for test suite and Phase 5+)
    # ------------------------------------------------------------------

    def get_snapshot(self) -> dict:
        """
        Return a point-in-time snapshot of all monitor metrics.

        Returns
        -------
        dict
            Contains all Phase 3 metrics plus the Phase 4 additions:
              last_window_connections  -- new TCP connections in the last window
              last_window_duration_sec -- actual elapsed seconds of the last window
              last_client_ip           -- most recently seen client IP
        """
        with self._lock:
            avg_size = (
                self.total_bytes / self.total_requests
                if self.total_requests > 0
                else 0.0
            )
            return {
                # Phase 3 metrics (unchanged)
                "total_requests":           self.total_requests,
                "total_bytes":              self.total_bytes,
                "total_connections":        self.total_connections,
                "active_connections":       self.active_connections,
                "requests_per_sec":         self.requests_per_sec,
                "bytes_per_sec":            self.bytes_per_sec,
                "avg_request_size":         avg_size,
                # Phase 4 additions
                "last_window_connections":  self._last_window_connections,
                "last_window_duration_sec": self._last_window_duration,
                "last_client_ip":           self._last_client_ip,
            }

    # ------------------------------------------------------------------
    # Internal: interval metric computation (called under self._lock)
    # ------------------------------------------------------------------

    def _compute_interval_metrics(self) -> None:
        """
        Compute per-interval rates and reset the interval counters.

        Called exclusively from _display_loop (inside self._lock).
        This ensures no other thread modifies the interval counters while
        the computation is in progress.

        Phase 4 additions:
          - Records actual elapsed time as _last_window_duration
          - Saves and resets _window_connections → _last_window_connections
        """
        now     = time.perf_counter()
        elapsed = now - self._interval_start

        # Phase 4: save actual window duration for dataset row
        self._last_window_duration = elapsed

        if elapsed > 0:
            self.requests_per_sec = self._interval_requests / elapsed
            self.bytes_per_sec    = self._interval_bytes    / elapsed
        else:
            self.requests_per_sec = 0.0
            self.bytes_per_sec    = 0.0

        # Phase 4: save and reset per-window connection counter
        self._last_window_connections = self._window_connections
        self._window_connections      = 0

        # Reset interval counters for the next window
        self._interval_requests = 0
        self._interval_bytes    = 0
        self._interval_start    = now

    # ------------------------------------------------------------------
    # Internal: display loop (background daemon thread)
    # ------------------------------------------------------------------

    def _display_loop(self) -> None:
        """
        Background thread: wakes every self._interval seconds to:
          1. Compute this window's aggregate metrics.
          2. Print the live dashboard.
          3. (Phase 4) Write one CSV observation row if collection is active.

        All counter reads happen inside self._lock.  Terminal I/O and CSV
        writes happen OUTSIDE self._lock to minimise lock-hold time.
        """
        while self._running:
            time.sleep(self._interval)

            # ----------------------------------------------------------
            # Step 1: Compute metrics and capture all values under lock
            # ----------------------------------------------------------
            with self._lock:
                self._compute_interval_metrics()

                # Snapshot all values needed for dashboard and dataset row
                rps       = self.requests_per_sec
                bps       = self.bytes_per_sec
                tot_req   = self.total_requests
                tot_bytes = self.total_bytes
                act_conn  = self.active_connections
                tot_conn  = self.total_connections
                avg_size  = tot_bytes / tot_req if tot_req > 0 else 0.0

                # Phase 4: window-level values for the CSV row
                win_dur  = self._last_window_duration
                win_conn = self._last_window_connections
                last_ip  = self._last_client_ip

                now_str = datetime.now().strftime("%H:%M:%S")

                if act_conn > 0 and rps > 0.5:
                    status = "ACTIVE"
                elif act_conn > 0:
                    status = "CONNECTED"
                else:
                    status = "IDLE"

                # Build Phase 4 observation dict (used below after lock release)
                obs_data = {
                    "window_duration_sec":        round(win_dur,  4),
                    "requests_per_sec":            round(rps,      2),
                    "bytes_per_sec":               round(bps,      2),
                    "avg_request_size_bytes":      round(avg_size, 2),
                    "active_connections":          act_conn,
                    "total_connections_in_window": win_conn,
                    "client_ip":                   last_ip,
                }

            # self._lock is now released
            # ----------------------------------------------------------
            # Step 2: Read dataset writer state (it has its own lock)
            # ----------------------------------------------------------
            writer     = self._dataset_writer   # set once at init -- always safe to read
            collecting = writer is not None and writer.is_active
            exp_id     = writer.current_experiment_id if collecting else ""
            rows       = writer.rows_written      if collecting else 0

            # ----------------------------------------------------------
            # Step 3: Build and print dashboard (terminal I/O outside lock)
            # ----------------------------------------------------------
            coll_status = (
                f"ACTIVE ({exp_id})  --  {rows} rows written"
                if collecting
                else "INACTIVE  (use client menu [6] to start)"
            )

            dashboard = (
                "\n"
                "+--------------------------------------------------+\n"
                "|       AI-NIDS NETWORK MONITOR -- PHASE 4         |\n"
                "+--------------------------------------------------+\n"
                "\n"
                f"  Status             : {status}\n"
                f"  Active Connections : {act_conn}\n"
                f"  Total Connections  : {tot_conn}\n"
                "\n"
                f"  Requests/sec       : {rps:.1f}\n"
                f"  Bytes/sec          : {self._fmt_bytes(bps)}/s\n"
                f"  Total Requests     : {tot_req}\n"
                f"  Total Bytes        : {self._fmt_bytes(tot_bytes)}\n"
                "\n"
                f"  Avg Request Size   : {avg_size:.0f} bytes (app-level, UTF-8)\n"
                "\n"
                f"  Dataset Collection : {coll_status}\n"
                "\n"
                f"  Last Updated       : {now_str}\n"
                "+--------------------------------------------------+\n"
            )

            try:
                os.system("cls" if os.name == "nt" else "clear")
            except Exception:
                pass
            print(dashboard)

            # ----------------------------------------------------------
            # Step 4: Write dataset observation (outside lock)
            # DatasetWriter.write_observation() checks is_active internally
            # under its own lock, so there is no TOCTOU issue.
            # ----------------------------------------------------------
            if writer is not None:
                writer.write_observation(obs_data)

    # ------------------------------------------------------------------
    # Internal: byte formatter
    # ------------------------------------------------------------------

    @staticmethod
    def _fmt_bytes(b: float) -> str:
        """Human-readable byte count (B / KB / MB)."""
        if b < 1024:
            return f"{b:.0f} B"
        if b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        return f"{b / (1024 * 1024):.1f} MB"
