# =============================================================================
# SERVER CONFIGURATION -- Phase 4
# =============================================================================
# This file holds all tunable parameters for the server.
# Change values here; do not hardcode them inside server.py.
#
# HOST
#   "0.0.0.0" means "listen on ALL available network interfaces".
#   This makes the server reachable from any PC on the LAN without
#   knowing which IP address this machine has at runtime.
#
# PORT
#   Any unused port between 1024-65535 is valid.
#   We use 5000 for this project.
#   Must match SERVER_PORT in client/config.py.
#
# BUFFER_SIZE
#   How many bytes are read from the socket in one recv() call.
#   This is the OS-level read size for the TCP receive buffer.
#   It is NOT the application payload size limit.
#
#   Application payload size is measured separately as:
#       len(payload.encode("utf-8"))
#   and stored in the "payload_size" field of each request.
#
# MAX_REQUESTS_PER_SESSION
#   Maximum number of structured requests the server will process
#   from a single client connection before closing it.
#
#   Calculation (Phase 3):
#     Highest traffic test = HIGH_RATE (500 req/s) * DURATION (10 s) = 5000
#     Add headroom for interactive menu usage within same session   = 1000
#     Total                                                        = 6000
#
# MONITOR_INTERVAL
#   How often (in seconds) the traffic monitor refreshes its display
#   and recomputes per-second rates. 1.0 second is a good balance
#   between responsiveness and readability.
# =============================================================================

HOST        = "0.0.0.0"   # Bind to all interfaces -- do NOT change this
PORT        = 5000         # TCP port the server listens on
BUFFER_SIZE = 4096         # OS recv() buffer size in bytes (not payload size)
BACKLOG     = 5            # OS connection queue depth

# Phase 3: calculated from HIGH_RATE(500) * DURATION(10) + headroom(1000)
MAX_REQUESTS_PER_SESSION = 6000

# Phase 3: traffic monitor display refresh interval (seconds)
MONITOR_INTERVAL = 1.0

# Phase 3: suppress verbose per-request logging when traffic rate exceeds
# this threshold (requests/sec). Keeps the terminal readable during
# traffic generation while still allowing detailed logs for single requests.
VERBOSE_LOG_THRESHOLD = 5.0

# =============================================================================
# Phase 4 -- Dataset Collection
# =============================================================================
#
# DATASET_PATH
#   Path to the CSV dataset file, relative to the project root.
#   The file is created automatically by DatasetWriter on first write.
#   All collection runs append to this same file (experiment_id
#   distinguishes individual runs).
#
# COLLECTION_WINDOW_SEC
#   Duration of one observation window.  Must match MONITOR_INTERVAL so that
#   exactly one dataset row is written per monitor tick.
# =============================================================================

import os

DATASET_PATH         = os.environ.get("AI_NIDS_DATASET_PATH", "data/network_traffic.csv")  # relative to project root
COLLECTION_WINDOW_SEC = 1.0                         # must equal MONITOR_INTERVAL
