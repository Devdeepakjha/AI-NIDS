"""
tests/test_live_forwarder_diagnostics.py
=============================================================================
Focused regression tests for:
  1. CloudEventForwarder diagnostics, deduplication, headers, and queue resilience.
  2. CloudTelemetryPipeline delta packet calculation and flow counting.
  3. FeatureGate protocol-specific feature unavailability on custom TCP flows.
=============================================================================
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import queue

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.live_inference import CloudEventForwarder, LiveInferencePipeline
from server.dashboard_server import CloudTelemetryPipeline
from ml.feature_gate import FeatureGate
from ml.flow_tracker import TCPFlow


class TestCloudForwarderDiagnostics(unittest.TestCase):
    def test_forwarder_deduplication_and_metrics(self):
        """Forwarder tracks enqueued counts and skips redundant identical packet signatures."""
        fwd = CloudEventForwarder(cloud_url="https://mock-endpoint.test/api/ingest", secret="test_key")
        
        # Mock worker thread to appear alive
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        fwd._worker_thread = mock_thread

        event = {
            "flow_id": "127.0.0.1:5000 -> 127.0.0.1:54321",
            "spkts": 2,
            "dpkts": 2,
            "gate_status": "INVALID_FEATURE_VECTOR",
            "timestamp": "2026-10-21T10:00:00.000",
            "inference_status": "SKIPPED",
        }

        # First enqueue succeeds
        fwd.enqueue(event)
        self.assertEqual(fwd.events_enqueued, 1)
        self.assertEqual(fwd.queue_pending, 1)

        # Duplicate identical snapshot is deduplicated (not enqueued again)
        fwd.enqueue(event)
        self.assertEqual(fwd.events_enqueued, 1)
        self.assertEqual(fwd.queue_pending, 1)

        # Updated packet snapshot is enqueued
        event_update = dict(event)
        event_update["spkts"] = 3
        fwd.enqueue(event_update)
        self.assertEqual(fwd.events_enqueued, 2)
        self.assertEqual(fwd.queue_pending, 2)

    def test_forwarder_queue_eviction_on_full(self):
        """When queue reaches capacity, oldest unforwarded event is evicted without blocking."""
        fwd = CloudEventForwarder(cloud_url="https://mock-endpoint.test", secret="sec")
        # Artificially set a tiny queue
        fwd.queue = queue.Queue(maxsize=2)
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        fwd._worker_thread = mock_thread

        e1 = {"flow_id": "f1", "spkts": 1, "dpkts": 1, "gate_status": "A"}
        e2 = {"flow_id": "f2", "spkts": 1, "dpkts": 1, "gate_status": "B"}
        e3 = {"flow_id": "f3", "spkts": 1, "dpkts": 1, "gate_status": "C"}

        fwd.enqueue(e1)
        fwd.enqueue(e2)
        self.assertEqual(fwd.queue_pending, 2)

        # Third enqueue evicts oldest (e1) without raising queue.Full
        fwd.enqueue(e3)
        self.assertEqual(fwd.queue_pending, 2)
        remaining = [fwd.queue.get_nowait(), fwd.queue.get_nowait()]
        self.assertEqual(remaining[0]["flow_id"], "f2")
        self.assertEqual(remaining[1]["flow_id"], "f3")


class TestCloudTelemetryPipelineDeduplication(unittest.TestCase):
    def test_flow_packet_delta_calculation(self):
        """Intermediate packet updates for the same flow do not inflate flow count or duplicate packet counts."""
        pipe = CloudTelemetryPipeline()

        # Step 1: Initial SYN/SYN-ACK (spkts=1, dpkts=1)
        evt1 = {
            "flow_id": "127.0.0.1:5000 -> 127.0.0.1:50001",
            "timestamp": "2026-10-21T10:00:01.000",
            "spkts": 1,
            "dpkts": 1,
            "inference_status": "SKIPPED",
            "gate_status": "INVALID_FEATURE_VECTOR"
        }
        ok, _ = pipe.ingest_event(evt1)
        self.assertTrue(ok)
        self.assertEqual(pipe.stats["flows_reconstructed"], 1)
        self.assertEqual(pipe.stats["packets_captured"], 2)

        # Step 2: Intermediate data packet (spkts=3, dpkts=2)
        evt2 = {
            "flow_id": "127.0.0.1:5000 -> 127.0.0.1:50001",
            "timestamp": "2026-10-21T10:00:02.000",
            "spkts": 3,
            "dpkts": 2,
            "inference_status": "SKIPPED",
            "gate_status": "INVALID_FEATURE_VECTOR"
        }
        ok, _ = pipe.ingest_event(evt2)
        self.assertTrue(ok)
        # Flow count remains 1 (same flow)
        self.assertEqual(pipe.stats["flows_reconstructed"], 1)
        # Delta: (3-1) + (2-1) = 3 new packets -> Total: 2 + 3 = 5 packets
        self.assertEqual(pipe.stats["packets_captured"], 5)

        # Step 3: A distinct second flow arrives
        evt3 = {
            "flow_id": "127.0.0.1:5000 -> 127.0.0.1:50002",
            "timestamp": "2026-10-21T10:00:03.000",
            "spkts": 2,
            "dpkts": 2,
            "inference_status": "SKIPPED",
            "gate_status": "INVALID_FEATURE_VECTOR"
        }
        ok, _ = pipe.ingest_event(evt3)
        self.assertTrue(ok)
        self.assertEqual(pipe.stats["flows_reconstructed"], 2)
        self.assertEqual(pipe.stats["packets_captured"], 9)


class TestFeatureGateRefusalSemantics(unittest.TestCase):
    def test_unavailable_features_strictly_refused(self):
        """FeatureGate enforces safe refusal when protocol-specific features are None."""
        gate = FeatureGate()
        # Mock features where the 5 protocol features are None
        features = {
            "dur": 0.05,
            "spkts": 4,
            "dpkts": 4,
            "sbytes": 200,
            "dbytes": 200,
            "ct_flw_http_mthd": None,
            "trans_depth": None,
            "response_body_len": None,
            "ct_ftp_cmd": None,
            "is_ftp_login": None,
        }
        provenance = {
            "ct_flw_http_mthd": {"status": "UNAVAILABLE", "reason": "No HTTP protocol on raw TCP"},
            "trans_depth": {"status": "UNAVAILABLE", "reason": "No HTTP transaction depth on raw TCP"},
            "response_body_len": {"status": "UNAVAILABLE", "reason": "No HTTP response body on raw TCP"},
            "ct_ftp_cmd": {"status": "UNAVAILABLE", "reason": "No FTP command stream on port 5000"},
            "is_ftp_login": {"status": "UNAVAILABLE", "reason": "No FTP login session on port 5000"},
        }
        is_valid, status, reasons = gate.validate(features, provenance)
        self.assertFalse(is_valid)
        self.assertEqual(status, "INVALID_FEATURE_VECTOR")
        self.assertTrue(any("ct_flw_http_mthd" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
