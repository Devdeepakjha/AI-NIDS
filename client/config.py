# =============================================================================
# CLIENT CONFIGURATION -- Phase 3
# =============================================================================
#
# BEFORE RUNNING THE CLIENT ON PC 1:
#   Set SERVER_IP to the LAN IP address of the Server PC.
#
#   On PC 2, open a terminal and run:
#       ipconfig
#   Look for "IPv4 Address" under Wi-Fi or Ethernet.
#   It will look like 192.168.x.x
#
# =============================================================================

# IP address of the machine running server/server.py
# Use "127.0.0.1" for local single-machine testing.
# Change to the actual LAN IP for two-PC demo (e.g. "192.168.1.10").
SERVER_IP   = "127.0.0.1"   # <-- CHANGE FOR TWO-PC DEMO

# Must match PORT in server/config.py
SERVER_PORT = 5000

# OS recv() buffer size.
# This is NOT the application payload size.
BUFFER_SIZE = 4096

# Default payload text sent in a normal request.
DEFAULT_PAYLOAD = "Hello Server! This is a structured Phase 2 request."

# Number of requests sent when the user chooses "Send Multiple Requests".
MULTI_REQUEST_COUNT = 5

# =============================================================================
# Phase 3 -- Traffic Generation Profiles
# =============================================================================
#
# These are TARGET rates, not guaranteed rates.
# The actual achieved rate depends on system performance, network latency,
# OS timer resolution (Windows ~15ms), and server processing speed.
#
# The client always reports both the target rate and the actual achieved rate.
# The server's independently observed rate is the source of truth.
#
# NORMAL_RATE : Low request frequency  (~10 req/sec)
# MEDIUM_RATE : Moderate frequency     (~100 req/sec)
# HIGH_RATE   : High controlled load   (~500 req/sec target)
#
# TRAFFIC_DURATION : How long each traffic generation run lasts (seconds)
# =============================================================================

NORMAL_RATE = 10       # target requests per second
MEDIUM_RATE = 100      # target requests per second
HIGH_RATE   = 500      # target requests per second

TRAFFIC_DURATION = 10  # seconds per traffic generation run
