"""
ml/env_discovery.py
=============================================================================
Phase 6.5: Environment Discovery for Packet-Level Telemetry Feasibility.

Performs a structured, reproducible probe of the current OS environment
to determine whether UNSW-NB15 Category C feature extraction via packet
capture is technically achievable.

Category C features (21 total) require packet/kernel-level access:
  spkts, dpkts, rate, sttl, dttl, sloss, dloss, sinpkt, dinpkt,
  sjit, djit, swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
  smean, dmean, ct_state_ttl

Three prerequisites must ALL be present simultaneously:
  1. Npcap or WinPcap kernel packet capture driver
  2. Administrator / root privileges
  3. A packet capture Python library (scapy, pyshark, or dpkt)

Environment classification:
  BLOCKED   - All prerequisites absent; packet capture impossible.
  PARTIAL   - Some capabilities present but insufficient for reliable capture.
  AVAILABLE - Full packet capture stack is present.

Implementation rules:
  - Standard library ONLY (os, socket, ctypes, importlib, json, platform).
  - NO external pip packages required or installed.
  - NO fabrication of feature values.
  - Result is cached (functools.lru_cache) after first call per process.
=============================================================================
"""

import ctypes
import importlib.util
import json
import os
import platform
import socket
import sys
from functools import lru_cache

# Canonical Npcap / WinPcap DLL locations on Windows
_NPCAP_DLL_PATHS = [
    r"C:\Windows\System32\Npcap\wpcap.dll",
    r"C:\Windows\System32\wpcap.dll",
    r"C:\Windows\SysWOW64\wpcap.dll",
    r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
]

# Packet capture Python libraries to probe (no install attempted)
_CAPTURE_LIBRARIES = ["scapy", "pyshark", "dpkt", "pypcap", "pcapy"]

# Project root (one level above ml/)
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Individual probe functions
# ---------------------------------------------------------------------------

def _probe_npcap_dll() -> dict:
    """
    Check for Npcap / WinPcap kernel driver DLL presence.

    Checks all canonical installation paths. Presence of the DLL indicates
    the kernel-level packet capture driver is installed.
    """
    found_paths = [p for p in _NPCAP_DLL_PATHS if os.path.exists(p)]
    return {
        "npcap_dll_found": bool(found_paths),
        "npcap_dll_paths_checked": list(_NPCAP_DLL_PATHS),
        "npcap_dll_found_at": found_paths if found_paths else None,
    }


def _probe_admin_privileges() -> dict:
    """
    Check whether the current process runs with administrator / root privileges.

    On Windows: uses ctypes.windll.shell32.IsUserAnAdmin().
    On POSIX:   uses os.getuid() == 0.
    """
    is_admin = False
    method = "unknown"
    error = None
    try:
        if platform.system() == "Windows":
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            method = "ctypes.windll.shell32.IsUserAnAdmin()"
        else:
            is_admin = (os.getuid() == 0)
            method = "os.getuid() == 0"
    except AttributeError as exc:
        error = f"AttributeError: {exc}"
        method = "check_unavailable"
    except Exception as exc:
        error = f"Unexpected: {exc}"
    return {
        "is_admin": is_admin,
        "privilege_check_method": method,
        "privilege_check_error": error,
    }


def _probe_raw_socket() -> dict:
    """
    Attempt to create an AF_INET SOCK_RAW socket to test kernel privileges.

    On Windows (non-admin): raises PermissionError [WinError 10013].
    On Windows (admin, no Npcap): may succeed but cannot sniff loopback.
    On Linux (admin): succeeds.
    """
    available = False
    error_detail = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        available = True
    except PermissionError as exc:
        error_detail = f"PermissionError: {exc}"
    except OSError as exc:
        error_detail = f"OSError: {exc}"
    except Exception as exc:
        error_detail = f"Unexpected: {exc}"
    return {
        "raw_socket_available": available,
        "raw_socket_error": error_detail,
    }


def _probe_promiscuous_sniffer() -> dict:
    """
    Attempt to bind a raw IP socket with IP_HDRINCL for promiscuous capture.

    This is the specific socket configuration required for IP-layer sniffing
    on 127.0.0.1. On Windows without Npcap + admin, this fails.
    """
    available = False
    error_detail = None
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind(("127.0.0.1", 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.close()
        available = True
    except PermissionError as exc:
        error_detail = f"PermissionError: {exc}"
    except OSError as exc:
        error_detail = f"OSError: {exc}"
    except Exception as exc:
        error_detail = f"Unexpected: {exc}"
    return {
        "promiscuous_sniffer_available": available,
        "promiscuous_sniffer_error": error_detail,
    }


def _probe_capture_libraries() -> dict:
    """
    Check availability of packet capture Python libraries via importlib.

    No import is executed; only import spec discovery is performed.
    This avoids loading heavy libraries and avoids triggering DLL errors.
    """
    lib_availability = {}
    for lib in _CAPTURE_LIBRARIES:
        spec = importlib.util.find_spec(lib)
        lib_availability[lib] = spec is not None

    return {
        "scapy_available": lib_availability.get("scapy", False),
        "pyshark_available": lib_availability.get("pyshark", False),
        "dpkt_available": lib_availability.get("dpkt", False),
        "pypcap_available": lib_availability.get("pypcap", False),
        "pcapy_available": lib_availability.get("pcapy", False),
        "any_capture_library_available": any(lib_availability.values()),
        "library_check_detail": lib_availability,
    }


# ---------------------------------------------------------------------------
# Status classification
# ---------------------------------------------------------------------------

def _classify_status(
    npcap: dict, admin: dict, raw: dict, libs: dict
) -> tuple:
    """
    Determine BLOCKED / PARTIAL / AVAILABLE from probe results.

    Returns
    -------
    (status: str, block_reason: str)
      block_reason is empty string when status is "AVAILABLE".
    """
    has_driver = npcap["npcap_dll_found"]
    has_admin = admin["is_admin"]
    has_raw = raw["raw_socket_available"]
    has_lib = libs["any_capture_library_available"]

    # Full stack present
    if has_driver and has_lib and (has_admin or has_raw):
        return "AVAILABLE", ""

    # All three prerequisites missing → hard block
    if not has_driver and not has_lib and not has_raw:
        paths_str = ", ".join(_NPCAP_DLL_PATHS)
        raw_err = raw["raw_socket_error"] or "unknown"
        return (
            "BLOCKED",
            (
                "Packet capture is impossible in this environment. "
                f"No Npcap/WinPcap kernel driver found (checked: {paths_str}). "
                "No packet capture Python library installed "
                f"(checked: {', '.join(_CAPTURE_LIBRARIES)}). "
                f"Raw socket creation failed: {raw_err}. "
                "All three prerequisites for UNSW-NB15 Category C feature "
                "extraction are simultaneously absent."
            ),
        )

    # At least one prerequisite present but not all → partial
    reasons = []
    if not has_driver:
        reasons.append("Npcap/WinPcap driver not installed")
    if not has_lib:
        reasons.append("no packet capture library (scapy, pyshark, dpkt)")
    if not has_admin and not has_raw:
        reasons.append("no administrator privileges or raw socket access")

    return (
        "PARTIAL",
        (
            "Partial capability present but insufficient for UNSW-NB15 Category C "
            f"feature extraction: {'; '.join(reasons)}."
        ),
    )


# ---------------------------------------------------------------------------
# Upgrade path definition
# ---------------------------------------------------------------------------

def _build_upgrade_path(npcap: dict, admin: dict, libs: dict) -> dict:
    """
    Construct a structured description of what is required to enable
    Category C packet-level feature extraction.
    """
    npcap_status = "INSTALLED" if npcap["npcap_dll_found"] else "NOT INSTALLED"
    scapy_status = "INSTALLED" if libs["scapy_available"] else "NOT INSTALLED"
    admin_status = "ADMIN" if admin["is_admin"] else "NOT ADMIN"

    return {
        "step_1_install_npcap": {
            "description": (
                "Install the Npcap kernel packet capture driver (Windows). "
                "Npcap enables user-space access to the Windows Packet Filter "
                "and is required for loopback (127.0.0.1) packet capture."
            ),
            "download_url": "https://npcap.com/#download",
            "verify_path": r"C:\Windows\System32\Npcap\wpcap.dll",
            "required": True,
            "current_status": npcap_status,
        },
        "step_2_install_scapy": {
            "description": (
                "Install the Scapy packet manipulation library. "
                "Scapy uses Npcap on Windows to send and receive raw packets."
            ),
            "install_command": "pip install scapy",
            "required": True,
            "current_status": scapy_status,
        },
        "step_3_run_as_administrator": {
            "description": (
                "Run the server process with Administrator privileges. "
                "On Windows, Npcap-based loopback capture requires elevation."
            ),
            "required": True,
            "current_status": admin_status,
        },
        "cat_c_features_unlocked": [
            "spkts", "dpkts", "rate", "sttl", "dttl",
            "sloss", "dloss", "sinpkt", "dinpkt",
            "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
            "tcprtt", "synack", "ackdat",
            "smean", "dmean", "ct_state_ttl",
        ],
        "cat_c_feature_count": 21,
        "upgrade_note": (
            "Once all three steps are satisfied, ml/feature_bridge.py can be "
            "extended to capture and parse raw Ethernet/IP/TCP frames on the "
            "loopback interface, extracting all 21 Category C features with "
            "full UNSW-NB15 semantic fidelity. Until then, the system correctly "
            "refuses live ML inference per the no-fabrication rule."
        ),
    }


# ---------------------------------------------------------------------------
# Main discovery function (cached)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def discover_packet_capture_environment() -> dict:
    """
    Run all environment probes and return a structured, machine-readable report.

    Result is cached after the first call (lru_cache) since OS state does not
    change within a single process lifetime.

    Returns
    -------
    dict with the following top-level keys:
        phase            : str  -- "Phase 6.5"
        discovery_reason : str  -- why this was run
        platform_info    : dict -- OS, Python, machine
        npcap            : dict -- Npcap/WinPcap DLL probe results
        privileges       : dict -- admin/root privilege probe results
        raw_socket       : dict -- SOCK_RAW creation probe results
        promiscuous_sniffer : dict -- promiscuous mode probe results
        capture_libraries   : dict -- scapy/pyshark/dpkt availability
        packet_capture_status : str -- "BLOCKED" | "PARTIAL" | "AVAILABLE"
        block_reason     : str  -- human-readable explanation (empty if AVAILABLE)
        cat_c_upgrade_path : dict -- structured upgrade path to enable Cat C features
    """
    npcap = _probe_npcap_dll()
    admin = _probe_admin_privileges()
    raw = _probe_raw_socket()
    promisc = _probe_promiscuous_sniffer()
    libs = _probe_capture_libraries()
    status, reason = _classify_status(npcap, admin, raw, libs)
    upgrade = _build_upgrade_path(npcap, admin, libs)

    return {
        "phase": "Phase 6.5",
        "discovery_reason": (
            "Determine whether UNSW-NB15 Category C (packet/kernel-level) "
            "feature extraction is technically feasible in this environment."
        ),
        "platform_info": {
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "machine": platform.machine(),
            "python_version": sys.version,
            "python_executable": sys.executable,
        },
        "npcap": npcap,
        "privileges": admin,
        "raw_socket": raw,
        "promiscuous_sniffer": promisc,
        "capture_libraries": libs,
        "packet_capture_status": status,
        "block_reason": reason,
        "cat_c_upgrade_path": upgrade,
    }


# ---------------------------------------------------------------------------
# Module-level constant — evaluated at import time (uses cached result)
# ---------------------------------------------------------------------------

#: Packet capture status in the current environment.
#: One of: "BLOCKED", "PARTIAL", "AVAILABLE".
#: Set at module import time using the cached discovery result.
PACKET_CAPTURE_STATUS: str = discover_packet_capture_environment()["packet_capture_status"]


# ---------------------------------------------------------------------------
# Report persistence
# ---------------------------------------------------------------------------

def write_env_report(output_path: str = None) -> str:
    """
    Write the environment discovery report to models/env_discovery_report.json.

    Parameters
    ----------
    output_path : str, optional
        Full destination file path. Defaults to
        ``<project_root>/models/env_discovery_report.json``.

    Returns
    -------
    str
        Absolute path of the written JSON file.
    """
    if output_path is None:
        output_path = os.path.join(_PROJECT_ROOT, "models", "env_discovery_report.json")
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    report = discover_packet_capture_environment()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    report = discover_packet_capture_environment()
    out = write_env_report()

    print()
    print("=" * 70)
    print("PHASE 6.5 — PACKET CAPTURE ENVIRONMENT DISCOVERY REPORT")
    print("=" * 70)
    print(f"  OS:                        {report['platform_info']['os']} "
          f"{report['platform_info']['os_release']}")
    print(f"  Administrator:             {report['privileges']['is_admin']}")
    print(f"  Npcap DLL Found:           {report['npcap']['npcap_dll_found']}")
    print(f"  Raw Socket Available:      {report['raw_socket']['raw_socket_available']}")
    print(f"  Promiscuous Sniffer:       {report['promiscuous_sniffer']['promiscuous_sniffer_available']}")
    print(f"  Scapy Available:           {report['capture_libraries']['scapy_available']}")
    print(f"  Any Capture Library:       {report['capture_libraries']['any_capture_library_available']}")
    print()
    print(f"  PACKET_CAPTURE_STATUS:     {report['packet_capture_status']}")
    if report["block_reason"]:
        print()
        print("  Block Reason:")
        reason_lines = report["block_reason"].split(". ")
        for line in reason_lines:
            if line:
                print(f"    - {line.strip()}.")
    print()
    print(f"  Report written to: {out}")
    print("=" * 70)
    print()
