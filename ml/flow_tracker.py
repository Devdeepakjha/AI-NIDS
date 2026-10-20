"""
ml/flow_tracker.py
=============================================================================
Phase 6.6: TCP Flow Reconstruction from Live Packet Telemetry.

Reconstructs bidirectional TCP flows from raw packet records.
Tracks flow lifecycle, timing metrics, handshake round-trip times,
window sizes, sequence numbers, packet inter-arrival times, jitter,
and state transitions according to transport-layer semantics.
=============================================================================
"""

import time
import math
import statistics
import threading
from typing import Dict, Tuple, List, Optional, Any


class TCPFlow:
    """
    Represents a single bidirectional TCP flow between a client and server.
    """

    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, start_time: float):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.proto = "tcp"

        self.start_time = start_time
        self.last_time = start_time

        # Packet and byte counts
        self.spkts = 0
        self.dpkts = 0
        self.sbytes = 0
        self.dbytes = 0
        self.s_payload_bytes = 0
        self.d_payload_bytes = 0

        # Detailed packet logs for statistical derivation
        self.src_pkt_times: List[float] = []
        self.dst_pkt_times: List[float] = []
        self.src_pkt_lens: List[int] = []
        self.dst_pkt_lens: List[int] = []

        # Handshake timing & base sequence numbers
        self.syn_time: Optional[float] = None
        self.synack_time: Optional[float] = None
        self.ack_time: Optional[float] = None
        self.stcpb: int = 0
        self.dtcpb: int = 0
        self.swin: int = 0
        self.dwin: int = 0

        # TTL values
        self.sttl: int = 0
        self.dttl: int = 0

        # Retransmission tracking
        self.src_seen_seqs: set = set()
        self.dst_seen_seqs: set = set()
        self.sloss: int = 0
        self.dloss: int = 0

        # Flow state: START, REQ, CON, FIN, RST, CLO
        self.state: str = "START"
        self.closed: bool = False
        self.close_time: Optional[float] = None

    def add_packet(self, pkt: Dict[str, Any]) -> None:
        """Process a packet belonging to this flow."""
        pkt_time = pkt["timestamp"]
        pkt_len = pkt.get("ip_len", 0)
        payload_len = pkt.get("payload_len", 0)
        seq = pkt.get("tcp_seq", 0)
        win = pkt.get("tcp_window", 0)
        ttl = pkt.get("ip_ttl", 0)

        self.last_time = max(self.last_time, pkt_time)

        # Is this packet from client (src) or server (dst)?
        is_client = (pkt["src_ip"] == self.src_ip and pkt["src_port"] == self.src_port)

        if is_client:
            self.spkts += 1
            self.sbytes += pkt_len
            self.s_payload_bytes += payload_len
            self.src_pkt_times.append(pkt_time)
            self.src_pkt_lens.append(pkt_len)
            self.sttl = ttl

            # Retransmission check (if payload > 0 and seq seen before)
            if payload_len > 0:
                if seq in self.src_seen_seqs:
                    self.sloss += 1
                else:
                    self.src_seen_seqs.add(seq)

            # Handshake client SYN
            if pkt["has_syn"] and not pkt["has_ack"]:
                self.syn_time = pkt_time
                self.stcpb = seq
                self.swin = win
                self.state = "REQ"

            # Client ACK completing handshake
            elif pkt["has_ack"] and not pkt["has_syn"] and not pkt["has_fin"] and not pkt["has_rst"]:
                if self.synack_time and not self.ack_time:
                    self.ack_time = pkt_time
                    self.state = "CON"

            if pkt["has_fin"]:
                self.state = "FIN"
            if pkt["has_rst"]:
                self.state = "RST"
                self.closed = True
                self.close_time = pkt_time

        else:
            # Server packet
            self.dpkts += 1
            self.dbytes += pkt_len
            self.d_payload_bytes += payload_len
            self.dst_pkt_times.append(pkt_time)
            self.dst_pkt_lens.append(pkt_len)
            self.dttl = ttl

            if payload_len > 0:
                if seq in self.dst_seen_seqs:
                    self.dloss += 1
                else:
                    self.dst_seen_seqs.add(seq)

            # Server SYN-ACK
            if pkt["has_syn"] and pkt["has_ack"]:
                self.synack_time = pkt_time
                self.dtcpb = seq
                self.dwin = win
                self.state = "CON"

            if pkt["has_fin"]:
                self.state = "FIN"
            if pkt["has_rst"]:
                self.state = "RST"
                self.closed = True
                self.close_time = pkt_time

    @property
    def duration(self) -> float:
        """Total flow duration in seconds."""
        dur = self.last_time - self.start_time
        return max(0.0, dur)

    def get_inter_packet_times(self, times: List[float]) -> List[float]:
        """Return list of inter-packet arrival times in milliseconds."""
        if len(times) < 2:
            return []
        sorted_times = sorted(times)
        return [(t2 - t1) * 1000.0 for t1, t2 in zip(sorted_times[:-1], sorted_times[1:])]

    def get_jitter(self, times: List[float]) -> float:
        """Compute jitter in milliseconds (mean difference of consecutive intervals)."""
        intervals = self.get_inter_packet_times(times)
        if len(intervals) < 2:
            return 0.0
        diffs = [abs(i2 - i1) for i1, i2 in zip(intervals[:-1], intervals[1:])]
        return float(statistics.mean(diffs)) if diffs else 0.0

    def get_handshake_metrics(self) -> Tuple[float, float, float]:
        """
        Return (synack, ackdat, tcprtt) in seconds.
        synack: time between SYN and SYN-ACK
        ackdat: time between SYN-ACK and ACK
        tcprtt: synack + ackdat
        """
        synack = 0.0
        ackdat = 0.0
        if self.syn_time and self.synack_time and self.synack_time >= self.syn_time:
            synack = self.synack_time - self.syn_time
        if self.synack_time and self.ack_time and self.ack_time >= self.synack_time:
            ackdat = self.ack_time - self.synack_time
        tcprtt = synack + ackdat
        return synack, ackdat, tcprtt


class FlowTracker:
    """
    Thread-safe registry reconstructing active and completed TCP flows.
    """

    def __init__(self, flow_timeout_sec: float = 10.0):
        self.flow_timeout_sec = flow_timeout_sec
        self._flows: Dict[Tuple[str, int, str, int], TCPFlow] = {}
        self._completed_flows: List[TCPFlow] = []
        self._lock = threading.Lock()
        self._total_flows_count = 0

    @property
    def total_flows_count(self) -> int:
        with self._lock:
            return self._total_flows_count

    @property
    def active_flows_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def process_packet(self, pkt: Dict[str, Any]) -> Optional[TCPFlow]:
        """
        Ingest a packet and update its corresponding flow.
        Returns the updated TCPFlow instance.
        """
        src_ip = pkt["src_ip"]
        src_port = pkt["src_port"]
        dst_ip = pkt["dst_ip"]
        dst_port = pkt["dst_port"]

        forward_key = (src_ip, src_port, dst_ip, dst_port)
        reverse_key = (dst_ip, dst_port, src_ip, src_port)

        with self._lock:
            flow = None
            if forward_key in self._flows:
                flow = self._flows[forward_key]
            elif reverse_key in self._flows:
                flow = self._flows[reverse_key]
            else:
                # New flow: determine initiator
                # If packet is client SYN or connecting to known server port, assume forward
                flow = TCPFlow(src_ip, src_port, dst_ip, dst_port, pkt["timestamp"])
                self._flows[forward_key] = flow
                self._total_flows_count += 1

            flow.add_packet(pkt)
            return flow

    def get_active_flows(self) -> List[TCPFlow]:
        with self._lock:
            return list(self._flows.values())

    def get_completed_flows(self) -> List[TCPFlow]:
        with self._lock:
            return list(self._completed_flows)

    def cleanup_idle_flows(self, current_time: Optional[float] = None) -> List[TCPFlow]:
        """
        Remove flows that have closed or timed out.
        Returns the list of retired flows.
        """
        now = current_time or time.time()
        retired = []
        with self._lock:
            keys_to_remove = []
            for key, flow in self._flows.items():
                if flow.closed or (now - flow.last_time > self.flow_timeout_sec):
                    keys_to_remove.append(key)
                    retired.append(flow)
                    self._completed_flows.append(flow)

            for key in keys_to_remove:
                del self._flows[key]

            # Keep completed flows list capped at 1000
            if len(self._completed_flows) > 1000:
                self._completed_flows = self._completed_flows[-1000:]

        return retired

    def reset(self) -> None:
        """Clear all active and completed flows."""
        with self._lock:
            self._flows.clear()
            self._completed_flows.clear()
            self._total_flows_count = 0
