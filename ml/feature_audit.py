"""
ml/feature_audit.py
=============================================================================
Phase 6: Feature Availability Audit for UNSW-NB15 vs Live TCP Architecture.

Classifies every Phase 5 model input feature into:
  Category A: DIRECTLY OBSERVABLE
    Can be measured directly from the current TCP socket architecture.
  Category B: LEGITIMATELY DERIVABLE
    Can be calculated from information already available or from additional
    measurements legitimately added to the server/monitor.
  Category C: NOT OBSERVABLE
    Cannot be obtained from the application-layer TCP socket architecture
    without packet sniffing (promiscuous mode/pcap) or kernel TCP hooks.
    Fabrication of these features is STRICTLY FORBIDDEN.
=============================================================================
"""

import json
import os

AUDIT_RESULTS = {
    # -----------------------------------------------------------------------
    # CATEGORICAL FEATURES (3 features)
    # -----------------------------------------------------------------------
    "proto": {
        "category": "A_DIRECTLY_OBSERVABLE",
        "definition": "Transaction protocol (e.g. tcp, udp, icmp).",
        "type": "categorical",
        "unit": "protocol_name",
        "measurement_point": "Server socket creation (SOCK_STREAM = tcp).",
        "is_direct": True,
        "derivation": "Directly observed from the active socket protocol (always 'tcp')."
    },
    "service": {
        "category": "A_DIRECTLY_OBSERVABLE",
        "definition": "Application service protocol (e.g. http, ftp, smtp, -).",
        "type": "categorical",
        "unit": "service_name",
        "measurement_point": "Application layer protocol framing (shared.protocol).",
        "is_direct": True,
        "derivation": "Observed from application message headers ('-' for custom TCP protocol)."
    },
    "state": {
        "category": "A_DIRECTLY_OBSERVABLE",
        "definition": "State of transaction / connection (e.g. CON, FIN, REQ, INT).",
        "type": "categorical",
        "unit": "state_code",
        "measurement_point": "Socket lifecycle management in handle_client().",
        "is_direct": True,
        "derivation": "Directly observed: 'CON' while connected, 'FIN' on graceful close."
    },

    # -----------------------------------------------------------------------
    # NUMERICAL FEATURES (39 features)
    # -----------------------------------------------------------------------
    "dur": {
        "category": "A_DIRECTLY_OBSERVABLE",
        "definition": "Record total flow duration in seconds.",
        "type": "numerical",
        "unit": "seconds",
        "measurement_point": "Connection lifecycle timer (perf_counter() at connect vs disconnect).",
        "is_direct": True,
        "derivation": "Directly observed: conn_end_time - conn_start_time."
    },
    "sbytes": {
        "category": "A_DIRECTLY_OBSERVABLE",
        "definition": "Source to destination transaction bytes.",
        "type": "numerical",
        "unit": "bytes",
        "measurement_point": "Server socket recv() counter.",
        "is_direct": True,
        "derivation": "Directly observed: sum of all bytes received from client socket."
    },
    "dbytes": {
        "category": "A_DIRECTLY_OBSERVABLE",
        "definition": "Destination to source transaction bytes.",
        "type": "numerical",
        "unit": "bytes",
        "measurement_point": "Server socket sendall() counter.",
        "is_direct": True,
        "derivation": "Directly observed: sum of all bytes sent by server in responses."
    },
    "spkts": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Source to destination IP packet count.",
        "type": "numerical",
        "unit": "packets",
        "measurement_point": "Network/IP layer (libpcap / raw sockets required).",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Application-layer TCP sockets (SOCK_STREAM) provide a byte stream; individual IP packets and TCP segments are handled internally by the OS kernel network stack."
    },
    "dpkts": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Destination to source IP packet count.",
        "type": "numerical",
        "unit": "packets",
        "measurement_point": "Network/IP layer (libpcap / raw sockets required).",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "TCP ACK and response segment packetization is handled asynchronously by the kernel network stack; not visible at application socket level."
    },
    "rate": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Total packets per second: (spkts + dpkts) / dur.",
        "type": "numerical",
        "unit": "packets/sec",
        "measurement_point": "Flow calculation.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "In UNSW-NB15, 'rate' is specifically IP packet rate, NOT application request rate. Depends on spkts and dpkts."
    },
    "sttl": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Source to destination time to live.",
        "type": "numerical",
        "unit": "hop count",
        "measurement_point": "IP header.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "IPv4 TTL header field is stripped by OS TCP stack and not exposed by default in standard Python socket read."
    },
    "dttl": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Destination to source time to live.",
        "type": "numerical",
        "unit": "hop count",
        "measurement_point": "IP header.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Generated by host kernel IP stack on outbound packets; not captured by application layer socket."
    },
    "sload": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Source bits per second: (sbytes * 8) / dur.",
        "type": "numerical",
        "unit": "bits/sec",
        "measurement_point": "Flow arithmetic from observable sbytes and dur.",
        "is_direct": False,
        "derivation": "Computed as (sbytes * 8) / max(dur, 1e-6)."
    },
    "dload": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Destination bits per second: (dbytes * 8) / dur.",
        "type": "numerical",
        "unit": "bits/sec",
        "measurement_point": "Flow arithmetic from observable dbytes and dur.",
        "is_direct": False,
        "derivation": "Computed as (dbytes * 8) / max(dur, 1e-6)."
    },
    "sloss": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Source packets dropped/retransmitted.",
        "type": "numerical",
        "unit": "packets",
        "measurement_point": "Kernel TCP retransmission queue.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "TCP loss recovery and retransmissions are hidden by the reliable transport abstraction."
    },
    "dloss": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Destination packets dropped/retransmitted.",
        "type": "numerical",
        "unit": "packets",
        "measurement_point": "Kernel TCP retransmission queue.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "TCP outbound loss recovery is hidden inside kernel."
    },
    "sinpkt": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Source inter-packet arrival time in milliseconds.",
        "type": "numerical",
        "unit": "milliseconds",
        "measurement_point": "Network card packet capture timestamp.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Requires per-packet NIC arrival timestamps; socket API coalesces segments into stream buffer."
    },
    "dinpkt": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Destination inter-packet arrival time in milliseconds.",
        "type": "numerical",
        "unit": "milliseconds",
        "measurement_point": "Network card packet capture timestamp.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Requires per-packet departure timestamps; not observable at application stream level."
    },
    "sjit": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Source jitter in milliseconds.",
        "type": "numerical",
        "unit": "milliseconds",
        "measurement_point": "Statistical analysis of packet inter-arrival times.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Depends on per-packet sinpkt arrival intervals."
    },
    "djit": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Destination jitter in milliseconds.",
        "type": "numerical",
        "unit": "milliseconds",
        "measurement_point": "Statistical analysis of packet inter-departure times.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Depends on per-packet dinpkt departure intervals."
    },
    "swin": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Source TCP window advertisement value.",
        "type": "numerical",
        "unit": "window size",
        "measurement_point": "TCP segment header.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "16-bit TCP header window advertisement is managed and consumed by OS TCP stack."
    },
    "stcpb": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Source TCP base sequence number.",
        "type": "numerical",
        "unit": "sequence number",
        "measurement_point": "TCP segment header.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "32-bit TCP sequence numbers are managed by kernel transport layer."
    },
    "dtcpb": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Destination TCP base sequence number.",
        "type": "numerical",
        "unit": "sequence number",
        "measurement_point": "TCP segment header.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "32-bit TCP sequence numbers are managed by kernel transport layer."
    },
    "dwin": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Destination TCP window advertisement value.",
        "type": "numerical",
        "unit": "window size",
        "measurement_point": "TCP segment header.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "TCP window advertisement in outbound segments is managed by OS kernel."
    },
    "tcprtt": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "TCP round trip time (SYN to SYN_ACK in seconds).",
        "type": "numerical",
        "unit": "seconds",
        "measurement_point": "Three-way handshake.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Handshake completes in kernel before accept() returns the socket to application."
    },
    "synack": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Time between SYN and SYN_ACK.",
        "type": "numerical",
        "unit": "seconds",
        "measurement_point": "Three-way handshake.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Kernel TCP handshake timing is not accessible via standard socket API."
    },
    "ackdat": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Time between SYN_ACK and ACK.",
        "type": "numerical",
        "unit": "seconds",
        "measurement_point": "Three-way handshake.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Kernel TCP handshake timing is not accessible via standard socket API."
    },
    "smean": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Mean packet size transmitted by source.",
        "type": "numerical",
        "unit": "bytes",
        "measurement_point": "Network layer (sbytes / spkts).",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "In UNSW-NB15, smean is average IP packet size, NOT application request size. Depends on spkts."
    },
    "dmean": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Mean packet size transmitted by destination.",
        "type": "numerical",
        "unit": "bytes",
        "measurement_point": "Network layer (dbytes / dpkts).",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Requires dpkts packet count."
    },
    "trans_depth": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Pipelined depth of request/response transactions.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Application framing.",
        "is_direct": False,
        "derivation": "In our synchronous request-response protocol, trans_depth is 1."
    },
    "response_body_len": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Actual payload content size transferred from server response.",
        "type": "numerical",
        "unit": "bytes",
        "measurement_point": "Server send_message handler.",
        "is_direct": False,
        "derivation": "Sum of UTF-8 application payload lengths returned by the server."
    },
    "ct_srv_src": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Number of connections to same service from source IP in 100 connection window.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Server connection tracker.",
        "is_direct": False,
        "derivation": "Tracked in rolling 100-connection history by client IP and service."
    },
    "ct_state_ttl": {
        "category": "C_NOT_OBSERVABLE",
        "definition": "Count of connections having same state and TTL.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Aggregation with TTL.",
        "is_direct": False,
        "derivation": None,
        "reason_unavailable": "Requires TTL which is unobservable at application layer."
    },
    "ct_dst_ltm": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Number of connections to destination in 100 connection window.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Server connection tracker.",
        "is_direct": False,
        "derivation": "Tracked in rolling 100-connection history for server."
    },
    "ct_src_dport_ltm": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Connections from source IP to destination port in 100 connection window.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Server connection tracker.",
        "is_direct": False,
        "derivation": "Tracked in rolling 100-connection history for client IP to server port."
    },
    "ct_dst_sport_ltm": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Connections to destination IP from source port in 100 connection window.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Server connection tracker.",
        "is_direct": False,
        "derivation": "Tracked in rolling 100-connection history for client ephemeral port."
    },
    "ct_dst_src_ltm": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Connections between source and destination IP in 100 connection window.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Server connection tracker.",
        "is_direct": False,
        "derivation": "Tracked in rolling 100-connection history for client IP to server IP."
    },
    "is_ftp_login": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "1 if FTP session logged in, 0 otherwise.",
        "type": "numerical",
        "unit": "binary_flag",
        "measurement_point": "Application protocol inspection.",
        "is_direct": False,
        "derivation": "Always 0 for non-FTP custom TCP protocol."
    },
    "ct_ftp_cmd": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Count of FTP commands in session.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Application protocol inspection.",
        "is_direct": False,
        "derivation": "Always 0 for non-FTP custom TCP protocol."
    },
    "ct_flw_http_mthd": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Count of HTTP methods (GET/POST) in session.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Application protocol inspection.",
        "is_direct": False,
        "derivation": "Count of HTTP-like request commands (0 for standard custom TCP)."
    },
    "ct_src_ltm": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Connections from source IP in 100 connection window.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Server connection tracker.",
        "is_direct": False,
        "derivation": "Tracked in rolling 100-connection history for client IP."
    },
    "ct_srv_dst": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "Connections to service from destination in 100 connection window.",
        "type": "numerical",
        "unit": "count",
        "measurement_point": "Server connection tracker.",
        "is_direct": False,
        "derivation": "Tracked in rolling 100-connection history for server service."
    },
    "is_sm_ips_ports": {
        "category": "B_LEGITIMATELY_DERIVABLE",
        "definition": "1 if source and destination IP and ports are equal, 0 otherwise.",
        "type": "numerical",
        "unit": "binary_flag",
        "measurement_point": "Socket address comparison.",
        "is_direct": False,
        "derivation": "1 if (client_ip == server_ip and client_port == server_port) else 0."
    }
}


def get_audit_summary() -> dict:
    """Returns a high-level summary of the feature availability audit.

    Phase 6.5 addition (additive only — all existing keys preserved):
      live_telemetry_status    : packet capture status from env_discovery
      packet_capture_upgrade_path : structured upgrade path to enable Cat C features
    """
    cat_a = [k for k, v in AUDIT_RESULTS.items() if v["category"] == "A_DIRECTLY_OBSERVABLE"]
    cat_b = [k for k, v in AUDIT_RESULTS.items() if v["category"] == "B_LEGITIMATELY_DERIVABLE"]
    cat_c = [k for k, v in AUDIT_RESULTS.items() if v["category"] == "C_NOT_OBSERVABLE"]

    # Phase 6.5: lazy import to avoid circular dependencies.
    # env_discovery uses stdlib only and is safe to import here.
    try:
        import importlib
        _env_mod = importlib.import_module("ml.env_discovery")
        _env_report = _env_mod.discover_packet_capture_environment()
        _telemetry_status = _env_report["packet_capture_status"]
        _upgrade_path = _env_report["cat_c_upgrade_path"]
        _block_reason = _env_report["block_reason"]
    except Exception:
        _telemetry_status = "UNKNOWN"
        _upgrade_path = {}
        _block_reason = ""

    return {
        # ----------------------------------------------------------------
        # Pre-existing keys (Phase 6 and earlier) — UNCHANGED
        # ----------------------------------------------------------------
        "total_model_features": len(AUDIT_RESULTS),
        "directly_observable_count": len(cat_a),
        "legitimately_derivable_count": len(cat_b),
        "not_observable_count": len(cat_c),
        "directly_observable_features": cat_a,
        "legitimately_derivable_features": cat_b,
        "not_observable_features": cat_c,
        "architectural_limitation_statement": (
            "Category C features represent kernel/packet-level network metrics (e.g. spkts, dpkts, "
            "sttl, tcprtt, jitter, window advertisement). Because our architecture operates at the "
            "application stream socket layer (SOCK_STREAM) without packet sniffing, these features cannot "
            "be legitimately observed. In accordance with strict cybersecurity integrity rules, fabrication "
            "of missing features is prohibited. The live bridge explicitly identifies this boundary."
        ),
        # ----------------------------------------------------------------
        # Phase 6.5 additions — environment telemetry status (additive only)
        # ----------------------------------------------------------------
        "live_telemetry_status": _telemetry_status,
        "live_telemetry_block_reason": _block_reason,
        "packet_capture_upgrade_path": _upgrade_path,
    }


def export_audit_artifact(output_path: str = None) -> str:
    """Export the feature availability audit to models/feature_availability_audit.json."""
    if output_path is None:
        models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
        output_path = os.path.join(models_dir, "feature_availability_audit.json")

    export_data = {
        "summary": get_audit_summary(),
        "feature_details": AUDIT_RESULTS
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
    return output_path


if __name__ == "__main__":
    out = export_audit_artifact()
    summary = get_audit_summary()
    print("=" * 70)
    print("UNSW-NB15 FEATURE AVAILABILITY AUDIT COMPLETE")
    print("=" * 70)
    print(f"Total Model Features:       {summary['total_model_features']}")
    print(f"  A. Directly Observable:   {summary['directly_observable_count']}")
    print(f"  B. Legitimately Derivable:{summary['legitimately_derivable_count']}")
    print(f"  C. Not Observable:        {summary['not_observable_count']}")
    print(f"Saved audit artifact to:    {out}")
    print("=" * 70)
