"""
ml/packet_capture.py
=============================================================================
Phase 6.6: Real Packet-Level Telemetry for AI-NIDS.

Captures real network packets on Windows loopback interface using Scapy/Npcap.
Captures IP and TCP header fields, flags, timestamps, and payload lengths
from running AI-NIDS traffic without modifying application sockets.

Thread-safe start/stop with configurable interface and BPF filter.
=============================================================================
"""

import os
import sys
import time
import queue
import threading
from typing import Optional, Callable, Dict, Any, List

# Suppress Scapy IPv6 / runtime warnings on import
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import (
        conf,
        AsyncSniffer,
        IP,
        TCP,
        Raw,
        Packet
    )
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        get_windows_if_list = None
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


DEFAULT_FILTER = "tcp port 5000"
DEFAULT_LOOPBACK_NAME = r"\Device\NPF_Loopback"


def find_loopback_interface() -> Optional[str]:
    """
    Find the Windows Npcap loopback interface name for Scapy.
    Returns the interface GUID/device string or None.
    """
    if not SCAPY_AVAILABLE:
        return None

    # Check env override first
    env_iface = os.environ.get("AI_NIDS_CAPTURE_INTERFACE")
    if env_iface:
        return env_iface

    # If Npcap is installed, look for NPF_Loopback or Npcap Loopback Adapter in conf.ifaces
    try:
        if hasattr(conf, "ifaces"):
            for dev_key, dev_obj in conf.ifaces.items():
                if dev_key == r"\Device\NPF_Loopback" or dev_key == "NPF_Loopback":
                    return dev_key
                desc = getattr(dev_obj, "description", "").lower()
                name = getattr(dev_obj, "name", "").lower()
                if "npcap loopback" in desc or "npcap loopback" in name:
                    return dev_key
    except Exception:
        pass

    # Check conf.loopback_name if resolvable in Scapy conf.ifaces
    try:
        if hasattr(conf, "loopback_name") and conf.loopback_name:
            if hasattr(conf, "ifaces"):
                for dev_key, dev_obj in conf.ifaces.items():
                    if getattr(dev_obj, "name", "") == str(conf.loopback_name):
                        return dev_key
    except Exception:
        pass

    return DEFAULT_LOOPBACK_NAME


class PacketCapture:
    """
    Manages live packet capture on the specified network interface.
    Extracts raw TCP/IP packet metadata and dispatches to registered callbacks.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_handler: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.interface = interface or find_loopback_interface() or DEFAULT_LOOPBACK_NAME
        self.bpf_filter = bpf_filter or os.environ.get("AI_NIDS_CAPTURE_FILTER", DEFAULT_FILTER)
        self.packet_handler = packet_handler

        self._sniffer: Optional[Any] = None
        self._is_running = False
        self.error_reason: Optional[str] = None
        self._lock = threading.Lock()
        self._packet_count = 0
        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_worker = threading.Event()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    def start(self) -> bool:
        """
        Start the packet capture thread.
        Returns True if successfully started and verified alive, False otherwise.
        """
        if not SCAPY_AVAILABLE:
            self.error_reason = "Scapy library not installed"
            print(f"[CAPTURE] {self.error_reason}")
            return False

        with self._lock:
            if self._is_running:
                return True

            try:
                self._stop_worker.clear()
                self._worker_thread = threading.Thread(
                    target=self._process_queue,
                    name="PacketCaptureWorker",
                    daemon=True
                )
                self._worker_thread.start()

                # Start AsyncSniffer
                self._sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._on_packet_received,
                    store=False
                )
                self._sniffer.start()

                # Verify that Scapy's internal sniffer thread actually started and didn't crash
                time.sleep(0.4)
                sniff_thread = getattr(self._sniffer, "thread", None)
                if not sniff_thread or not sniff_thread.is_alive():
                    exc = getattr(self._sniffer, "exception", None)
                    err_msg = (
                        f"Npcap driver not installed or packet sniffer thread died on '{self.interface}': {exc}"
                    )
                    self.error_reason = err_msg
                    print(f"[CAPTURE] ERROR: {err_msg}")
                    self._stop_worker.set()
                    self._is_running = False
                    return False

                self._is_running = True
                self.error_reason = None
                print(f"[CAPTURE] Packet capture started on '{self.interface}' with filter '{self.bpf_filter}'")
                return True
            except Exception as exc:
                self.error_reason = str(exc)
                print(f"[CAPTURE] Failed to start AsyncSniffer: {exc}")
                self._stop_worker.set()
                self._is_running = False
                return False

    def stop(self) -> None:
        """
        Stop the packet capture thread cleanly.
        """
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        self._stop_worker.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self._worker_thread = None
        print(f"[CAPTURE] Packet capture stopped. Total packets captured: {self._packet_count}")

    def _on_packet_received(self, pkt: Any) -> None:
        """Invoked by Scapy for every matching packet received."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Extract flags
        flags_int = int(tcp_layer.flags)
        flags_str = str(tcp_layer.flags)
        has_syn = bool(flags_int & 0x02)
        has_ack = bool(flags_int & 0x10)
        has_fin = bool(flags_int & 0x01)
        has_rst = bool(flags_int & 0x04)
        has_psh = bool(flags_int & 0x08)

        payload_bytes = len(tcp_layer.payload) if tcp_layer.payload else 0

        packet_info: Dict[str, Any] = {
            "timestamp": float(pkt.time),
            "src_ip": str(ip_layer.src),
            "dst_ip": str(ip_layer.dst),
            "src_port": int(tcp_layer.sport),
            "dst_port": int(tcp_layer.dport),
            "protocol": "tcp",
            "ip_len": int(ip_layer.len),
            "ip_ttl": int(ip_layer.ttl),
            "tcp_seq": int(tcp_layer.seq),
            "tcp_ack": int(tcp_layer.ack),
            "tcp_window": int(tcp_layer.window),
            "flags_int": flags_int,
            "flags_str": flags_str,
            "has_syn": has_syn,
            "has_ack": has_ack,
            "has_fin": has_fin,
            "has_rst": has_rst,
            "has_psh": has_psh,
            "payload_len": payload_bytes,
        }

        with self._lock:
            self._packet_count += 1

        try:
            self._packet_queue.put_nowait(packet_info)
        except queue.Full:
            pass

    def _process_queue(self) -> None:
        """Worker thread dispatching packets to handler without blocking sniffer."""
        while not self._stop_worker.is_set():
            try:
                pkt_info = self._packet_queue.get(timeout=0.2)
                if self.packet_handler:
                    try:
                        self.packet_handler(pkt_info)
                    except Exception as exc:
                        print(f"[CAPTURE] Error in packet_handler: {exc}")
                self._packet_queue.task_done()
            except queue.Empty:
                continue
