"""
tests/test_cloud_ingestion.py
=============================================================================
Unit & Integration Tests for Cloud Dashboard Telemetry Ingestion.

Tests:
  1. Authenticated ingestion accepts valid events (200 OK)
  2. Missing/wrong secret is rejected (401 Unauthorized)
  3. Malformed JSON payload is rejected (400 Bad Request)
  4. Missing required telemetry fields is rejected (400 Bad Request)
  5. Duplicate event handling
  6. Ingested events properly update telemetry statistics and recent event history
  7. Offline Authoritative Model demo remains operational and distinct
  8. CloudEventForwarder non-blocking queue behavior
=============================================================================
"""

import os
import sys
import json
import unittest
from datetime import datetime

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from server.dashboard_server import create_dashboard_app, CloudTelemetryPipeline
from ml.live_inference import CloudEventForwarder


class TestCloudIngestion(unittest.TestCase):
    def setUp(self):
        # Set a test secret
        os.environ["AI_NIDS_INGESTION_SECRET"] = "test-secret-key-12345"
        self.pipeline = CloudTelemetryPipeline()
        self.app = create_dashboard_app(self.pipeline)
        self.client = self.app.test_client()

    def tearDown(self):
        if "AI_NIDS_INGESTION_SECRET" in os.environ:
            del os.environ["AI_NIDS_INGESTION_SECRET"]

    def _sample_event(self, flow_id="192.168.1.5:54321 -> 192.168.1.10:5000", timestamp=None):
        return {
            "timestamp": timestamp or datetime.now().isoformat(),
            "flow_id": flow_id,
            "src_ip": "192.168.1.5",
            "src_port": 54321,
            "dst_ip": "192.168.1.10",
            "dst_port": 5000,
            "protocol": "tcp",
            "duration": 0.125,
            "spkts": 5,
            "dpkts": 4,
            "sbytes": 350,
            "dbytes": 280,
            "gate_status": "VALID",
            "inference_status": "PREDICTED",
            "prediction": "BENIGN",
            "probability": 0.05,
            "reasons": []
        }

    def test_01_authenticated_ingestion_success(self):
        """Valid event with correct secret returns 200 SUCCESS and updates telemetry."""
        event = self._sample_event()
        res = self.client.post(
            "/api/ingest",
            data=json.dumps(event),
            content_type="application/json",
            headers={"X-AI-NIDS-Secret": "test-secret-key-12345"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")

        # Verify telemetry statistics updated
        status = self.pipeline.get_status_summary()
        self.assertEqual(status["telemetry"]["packets_captured"], 9)
        self.assertEqual(status["telemetry"]["predictions_made"], 1)
        self.assertEqual(status["telemetry"]["benign_count"], 1)
        self.assertEqual(len(status["recent_events"]), 1)

    def test_02_unauthenticated_ingestion_rejected(self):
        """Missing or wrong secret returns 401 UNAUTHORIZED."""
        event = self._sample_event()

        # Missing secret
        res1 = self.client.post(
            "/api/ingest",
            data=json.dumps(event),
            content_type="application/json"
        )
        self.assertEqual(res1.status_code, 401)

        # Wrong secret
        res2 = self.client.post(
            "/api/ingest",
            data=json.dumps(event),
            content_type="application/json",
            headers={"X-AI-NIDS-Secret": "wrong-secret"}
        )
        self.assertEqual(res2.status_code, 401)

        # Bearer token format also supported
        res3 = self.client.post(
            "/api/ingest",
            data=json.dumps(event),
            content_type="application/json",
            headers={"Authorization": "Bearer test-secret-key-12345"}
        )
        self.assertEqual(res3.status_code, 200)

    def test_03_malformed_json_rejected(self):
        """Invalid JSON or non-dict body returns 400 BAD REQUEST."""
        res = self.client.post(
            "/api/ingest",
            data="not-valid-json",
            content_type="application/json",
            headers={"X-AI-NIDS-Secret": "test-secret-key-12345"}
        )
        self.assertEqual(res.status_code, 400)

    def test_04_missing_required_fields_rejected(self):
        """Missing mandatory telemetry fields returns 400 BAD REQUEST."""
        incomplete = {
            "timestamp": "2026-10-20T12:00:00",
            "src_ip": "127.0.0.1"
            # missing dst_ip, ports, protocol, inference_status
        }
        res = self.client.post(
            "/api/ingest",
            data=json.dumps(incomplete),
            content_type="application/json",
            headers={"X-AI-NIDS-Secret": "test-secret-key-12345"}
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Missing required telemetry fields", res.get_json()["error"])

    def test_05_duplicate_event_handling(self):
        """Exact identical duplicate event is safely ignored without double counting."""
        event = self._sample_event(flow_id="static-flow", timestamp="2026-10-20T12:00:00.000")
        res1 = self.client.post(
            "/api/ingest",
            data=json.dumps(event),
            content_type="application/json",
            headers={"X-AI-NIDS-Secret": "test-secret-key-12345"}
        )
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.get_json()["status"], "SUCCESS")

        # Second send of identical event
        res2 = self.client.post(
            "/api/ingest",
            data=json.dumps(event),
            content_type="application/json",
            headers={"X-AI-NIDS-Secret": "test-secret-key-12345"}
        )
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.get_json()["status"], "IGNORED")

        # Packet count should NOT have doubled
        status = self.pipeline.get_status_summary()
        self.assertEqual(status["telemetry"]["packets_captured"], 9)

    def test_06_authoritative_demo_operational(self):
        """Authoritative vector demo works and is explicitly labeled as offline benchmark."""
        res = self.client.post("/api/demo-authoritative")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["demo_type"], "OFFLINE_AUTHORITATIVE_MODEL_DEMO")
        self.assertIn("offline model benchmark", data["note"].lower())

    def test_07_cloud_forwarder_non_blocking_queue(self):
        """CloudEventForwarder buffers events into a queue without blocking."""
        forwarder = CloudEventForwarder(cloud_url="https://mock-domain.fake/api", secret="sec")
        self.assertEqual(forwarder.queue.qsize(), 0)
        # Calling enqueue before start or when offline does not block or throw
        forwarder.enqueue({"timestamp": "test", "src_ip": "1.1.1.1"})
        # Clean teardown
        forwarder.stop()


if __name__ == "__main__":
    unittest.main()
